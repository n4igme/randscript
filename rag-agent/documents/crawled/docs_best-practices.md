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
  * [](https://frida.re/docs/best-practices/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/best-practices.md)
# Best Practices
This section is meant to contain best practices and pitfalls commonly encountered when using Frida.
### String allocation (UTF-8/UTF-16/ANSI)
By reading the documentation, one might think that allocating/replacing strings is as simple as:
```
onEnter(args) {
  args[0].writeUtf8String('mystring');
}
```

However, this may not be possible because the string pointed to may:
  * Reside in a “read-only-data” section which gets mapped into the process’ address space as read-only;
  * Be longer than the string already there, so _writeUtf8String()_ causes a buffer-overflow and may corrupt unrelated memory.


Even if you could solve the former issue by using _Memory.protect()_ , there is a much better solution: allocate a new string and replace the argument instead.
There is however a pitfall: the value returned by _Memory.allocUtf8String()_ must be kept alive – it gets freed as soon as the JavaScript value gets garbage-collected. This means it needs to be kept alive for at least the duration of the function-call, and in some cases even longer; the exact semantics depend on how the API was designed.
With this in mind, a reliable way to do this would be:
```
onEnter(args) {
  const buf = Memory.allocUtf8String('mystring');
  this.buf = buf;
  args[0] = buf;
}
```

The way this works is that _this_ is bound to an object that is per-thread and per-invocation, and anything you store there will be available in _onLeave_ , and this even works in case of recursion. This way you can read arguments in _onEnter_ and access them later in _onLeave_. It is also the recommended way to keep memory allocations alive for the duration of the function-call.
If the function keeps the pointer around and also uses it after the function call has completed, one solution is to do it like this:
```
const myStringBuf = Memory.allocUtf8String('mystring');

Interceptor.attach(f, {
  onEnter(args) {
    args[0] = myStringBuf;
  }
});
```

### Reusing arguments
When reading arguments in the _onEnter_ callback, it is common to access each argument by their index. But what happens when an argument is accessed multiple times? Take for example this code:
```
Interceptor.attach(f, {
  onEnter(args) {
    if (!args[0].readUtf8String(4).includes('MZ')) {
      console.log(hexdump(args[0]));
    }
  }
});
```

In the above example the first argument is obtained from the _args_ array twice, and this is paying the cost of querying _frida-gum_ for this information twice. To avoid wasting precious CPU cycles when needing the same argument multiple times, it is best to store this information using a local variable:
```
Interceptor.attach(f, {
  onEnter(args) {
    const firstArg = args[0];
    if (!firstArg.readUtf8String(4).includes('MZ')) {
      console.log(hexdump(firstArg));
    }
  }
});
```

[Back](https://frida.re/docs/bridges/)
[Next](https://frida.re/docs/troubleshooting/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
