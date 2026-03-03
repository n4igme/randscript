  * [Overview](https://frida.re/)
  * [Docs](https://frida.re/docs/home/)
  * [News](https://frida.re/news/)
  * [Code](https://github.com/frida/frida)
  * [Contact](https://frida.re/contact/)


[ FЯIDA ![](https://frida.re/img/logotype.svg) ](https://frida.re/)
  * [Overview](https://frida.re/)
  * [Docs](https://frida.re/docs/home/)
  * [News](https://frida.re/news/)
  * [Code](https://github.com/frida/frida)
  * [Contact](https://frida.re/contact/)


Navigate the docs… Welcome Quick-start guide Installation Modes of Operation Gadget Hacking Stalker Presentations Functions Messages iOS Android Windows macOS Linux iOS Android JavaScript Frida CLI frida-ps frida-trace frida-discover frida-ls-devices frida-kill gum-graft JavaScript API C API Swift API Go API Bridges Best Practices Troubleshooting Building Footprint GSoC Ideas 2015 GSoD Ideas 2023 History
#### Getting Started
  * [Welcome](https://frida.re/docs/home/)
  * [Quick-start guide](https://frida.re/docs/quickstart/)
  * [Installation](https://frida.re/docs/installation/)
  * [Modes of Operation](https://frida.re/docs/modes/)
  * [Gadget](https://frida.re/docs/gadget/)
  * [Hacking](https://frida.re/docs/hacking/)
  * [Stalker](https://frida.re/docs/stalker/)
  * [Presentations](https://frida.re/docs/presentations/)


#### Tutorials
  * [Functions](https://frida.re/docs/functions/)
  * [Messages](https://frida.re/docs/messages/)
  * [iOS](https://frida.re/docs/ios/)
  * [Android](https://frida.re/docs/android/)


#### Examples
  * [Windows](https://frida.re/docs/examples/windows/)
  * [macOS](https://frida.re/docs/examples/macos/)
  * [Linux](https://frida.re/docs/examples/linux/)
  * [iOS](https://frida.re/docs/examples/ios/)
  * [Android](https://frida.re/docs/examples/android/)
  * [JavaScript](https://frida.re/docs/examples/javascript/)


#### Tools
  * [Frida CLI](https://frida.re/docs/frida-cli/)
  * [frida-ps](https://frida.re/docs/frida-ps/)
  * [frida-trace](https://frida.re/docs/frida-trace/)
  * [frida-discover](https://frida.re/docs/frida-discover/)
  * [frida-ls-devices](https://frida.re/docs/frida-ls-devices/)
  * [frida-kill](https://frida.re/docs/frida-kill/)
  * [gum-graft](https://frida.re/docs/gum-graft/)


#### API Reference
  * [JavaScript API](https://frida.re/docs/javascript-api/)
  * [C API](https://frida.re/docs/c-api/)
  * [Swift API](https://frida.re/docs/swift-api/)
  * [Go API](https://frida.re/docs/go-api/)
  * [Bridges](https://frida.re/docs/bridges/)


#### Miscellaneous
  * [Best Practices](https://frida.re/docs/best-practices/)
  * [Troubleshooting](https://frida.re/docs/troubleshooting/)
  * [Building](https://frida.re/docs/building/)
  * [Footprint](https://frida.re/docs/footprint/)


#### Meta
  * [](https://frida.re/docs/examples/javascript/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/examples/javascript.md)
# JavaScript
## Connect to a Node.js process’ V8 VM to inject arbitrary JS
```
const uv_default_loop = new NativeFunction(Module.getGlobalExportByName('uv_default_loop'), 'pointer', []);
const uv_async_init = new NativeFunction(Module.getGlobalExportByName('uv_async_init'), 'int', ['pointer', 'pointer', 'pointer']);
const uv_async_send = new NativeFunction(Module.getGlobalExportByName('uv_async_send'), 'int', ['pointer']);
const uv_close = new NativeFunction(Module.getGlobalExportByName('uv_close'), 'void', ['pointer', 'pointer']);
const uv_unref = new NativeFunction(Module.getGlobalExportByName('uv_unref'), 'void', ['pointer']);

const v8_Isolate_GetCurrent = new NativeFunction(Module.getGlobalExportByName('_ZN2v87Isolate10GetCurrentEv'), 'pointer', []);
const v8_Isolate_GetCurrentContext = new NativeFunction(Module.getGlobalExportByName('_ZN2v87Isolate17GetCurrentContextEv'), 'pointer', ['pointer']);

const v8_HandleScope_init = new NativeFunction(Module.getGlobalExportByName('_ZN2v811HandleScopeC1EPNS_7IsolateE'), 'void', ['pointer', 'pointer']);
const v8_HandleScope_finalize = new NativeFunction(Module.getGlobalExportByName('_ZN2v811HandleScopeD1Ev'), 'void', ['pointer']);

const v8_String_NewFromUtf8 = new NativeFunction(Module.getGlobalExportByName('_ZN2v86String11NewFromUtf8EPNS_7IsolateEPKcNS_13NewStringTypeEi'), 'pointer', ['pointer', 'pointer', 'int', 'int']);

const v8_Script_Compile = new NativeFunction(Module.getGlobalExportByName('_ZN2v86Script7CompileENS_5LocalINS_7ContextEEENS1_INS_6StringEEEPNS_12ScriptOriginE'), 'pointer', ['pointer', 'pointer', 'pointer']);
const v8_Script_Run = new NativeFunction(Module.getGlobalExportByName('_ZN2v86Script3RunENS_5LocalINS_7ContextEEE'), 'pointer', ['pointer', 'pointer']);

const NewStringType = {
  kNormal: 0,
  kInternalized: 1
};

const pending = [];

const processPending = new NativeCallback(function () {
  const isolate = v8_Isolate_GetCurrent();

  const scope = Memory.alloc(24);
  v8_HandleScope_init(scope, isolate);

  const context = v8_Isolate_GetCurrentContext(isolate);

  while (pending.length > 0) {
    const item = pending.shift();
    const source = v8_String_NewFromUtf8(isolate, Memory.allocUtf8String(item), NewStringType.kNormal, -1);
    const script = v8_Script_Compile(context, source, NULL);
    const result = v8_Script_Run(script, context);
  }

  v8_HandleScope_finalize(scope);
}, 'void', ['pointer']);

const onClose = new NativeCallback(function () {
  Script.unpin();
}, 'void', ['pointer']);

const handle = Memory.alloc(128);
uv_async_init(uv_default_loop(), handle, processPending);
uv_unref(handle);

Script.bindWeak(handle, () => {
  Script.pin();
  uv_close(handle, onClose);
});

function run(source) {
  pending.push(source);
  uv_async_send(handle);
}

run('console.log("Hello from Frida");');
```

## Trace function calls in a Perl 5 process
```
const pointerSize = Process.pointerSize;
const SV_OFFSET_FLAGS = pointerSize + 4;
const PVGV_OFFSET_NAMEHEK = 4 * pointerSize;

const SVt_PVGV = 9;

Interceptor.attach(Module.getGlobalExportByName('Perl_pp_entersub'), {
  onEnter(args) {
    const interpreter = args[0];
    const stack = interpreter.readPointer();

    const sub = stack.readPointer();

    const flags = sub.add(SV_OFFSET_FLAGS).readU32();
    const type = flags & 0xff;
    if (type === SVt_PVGV) {
      /*
       * Note: this console.log() is not ideal performance-wise,
       * a proper implementation would buffer and submit events
       * periodically with send().
       */
      console.log(GvNAME(sub) + '()');
    } else {
      // XXX: Do we need to handle other types?
    }
  }
});

function GvNAME(sv) {
  const body = sv.readPointer();
  const nameHek = body.add(PVGV_OFFSET_NAMEHEK).readPointer();
  return nameHek.add(8).readUtf8String();
}
```

_Please click “Improve this page” above and add an example. Thanks!_
[Back](https://frida.re/docs/examples/android/)
[Next](https://frida.re/docs/frida-cli/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
