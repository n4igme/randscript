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
  * [](https://frida.re/docs/history/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/history.md)
# History
Frida was born after [@oleavr](https://twitter.com/oleavr) and [@hsorbo](https://twitter.com/hsorbo) had been casually brainstorming about how they wish they could turn tedious manual reverse-engineering into something much more fun, productive, and interactive.
Having built [oSpy](https://github.com/oleavr/ospy) and other custom tools to scratch reverse-engineering itches, [@oleavr](https://twitter.com/oleavr) started piecing together [frida-gum](https://github.com/frida/frida-gum), a generic cross-platform code-instrumentation library for C. At the time it was limited to hooking functions and providing some tools to help developers write unit-tests for memory leaks and profiling on an extremely granular level. Later it was further improved and used to create Frida. The component [frida-core](https://github.com/frida/frida-core) would take care of all the nitty gritty details of injecting shared libraries into arbitrary processes, and maintaining a live two-way channel with the injected code running inside those processes. Inside that payload, [frida-gum](https://github.com/frida/frida-gum) would take care of hooking functions and providing a scripting runtime using the excellent [QuickJS](https://bellard.org/quickjs/) engine.
Later, in their not-so-ample spare time, [@oleavr](https://twitter.com/oleavr) and [@karltk](https://twitter.com/karltk) did some recreational pair-programming-hackathons that resulted in [huge improvements](http://blog.kalleberg.org/post/833101026/live-x86-code-instrumentation-with-frida) to [frida-gum](https://github.com/frida/frida-gum)’s code tracing engine, the so-called [Stalker](https://github.com/frida/frida-gum/blob/master/gum/backend-x86/gumstalker-x86.c). There were also Python bindings created. They started realizing that it was about time that people out there knew about the project, so further hackathons were devoted to piecing together a website and some much needed documentation.
Today, Frida should be a very helpful toolbox for anyone interested in dynamic instrumentation and/or reverse-engineering. There are now language bindings for [Node.js](https://github.com/frida/frida-node), [Python](https://github.com/frida/frida-python), [Swift](https://github.com/frida/frida-swift), [.NET](https://github.com/frida/frida-clr), [Qt/Qml](https://github.com/frida/frida-qml), [Go](https://github.com/frida/frida-go), and it is also possible to use Frida from C.
[Back](https://frida.re/docs/gsod-ideas-2023/)
Next
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
