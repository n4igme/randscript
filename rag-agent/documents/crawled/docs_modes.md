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
  * [](https://frida.re/docs/modes/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/modes.md)
# Modes of Operation
Frida provides dynamic instrumentation through its powerful instrumentation core Gum, which is written in C. Because such instrumentation logic is prone to change, you usually want to write it in a scripting language so you get a short feedback loop while developing and maintaining it. This is where GumJS comes into play. With just a few lines of C you can run a piece of JavaScript inside a runtime that has full access to Gum’s APIs, allowing you to hook functions, enumerate loaded libraries, their imported and exported functions, read and write memory, scan memory for patterns, etc.
## Table of contents
  1. [Injected](https://frida.re/docs/modes/#injected)
  2. [Embedded](https://frida.re/docs/modes/#embedded)
  3. [Preloaded](https://frida.re/docs/modes/#preloaded)


## Injected
Most of the time, however, you want to spawn an existing program, attach to a running program, or hijack one as it’s being spawned, and then run your instrumentation logic inside of it. As this is such a common way to use Frida, it is what most of our documentation focuses on. This functionality is provided by frida-core, which acts as a logistics layer that packages up GumJS into a shared library that it injects into existing software, and provides a two-way communication channel for talking to your scripts, if needed, and later unload them. Beside this core functionality, frida-core also lets you enumerate installed apps, running processes, and connected devices. The connected devices are typically iOS and Android devices where _frida-server_ is running. That component is essentially just a daemon that exposes frida-core over TCP, listening on _localhost:27042_ by default.
## Embedded
It is sometimes not possible to use Frida in [Injected](https://frida.re/docs/modes/#injected) mode, for example on jailed iOS and Android systems. For such cases we provide you with _frida-gadget_ , a shared library that you’re supposed to embed inside the program that you want to instrument. By simply loading the library it will allow you to interact with it remotely, using existing Frida-based tools like [frida-trace](https://frida.re/docs/frida-trace/). It also supports a fully autonomous approach where it can run scripts off the filesystem without any outside communication.
Read more about Gadget [here](https://frida.re/docs/gadget/).
## Preloaded
Perhaps you’re familiar with _LD_PRELOAD_ , or _DYLD_INSERT_LIBRARIES_? Wouldn’t it be cool if there was _JS_PRELOAD_? This is where _frida-gadget_ , the shared library discussed in the previous section, is really useful when configured to run autonomously by loading a script from the filesystem.
Read more about Gadget [here](https://frida.re/docs/gadget/).
[Back](https://frida.re/docs/installation/)
[Next](https://frida.re/docs/gadget/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
