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
  * [](https://frida.re/docs/frida-cli/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/frida-cli.md)
# Frida CLI
Frida CLI is a REPL interface that aims to emulate a lot of the nice features of IPython (or Cycript), which tries to get you closer to your code for rapid prototyping and easy debugging.
```
# Connect Frida to an iPad over USB and start debugging Safari
$ frida -U Safari

[USB::iPad 4::Safari]->
```

## An example session
```
# Connect Frida to a locally-running Calculator.app
$ frida Calculator

# Look at the local variables/context
[Local::ProcName::Calculator]-> <TAB>
Backtracer           Process
CpuContext           Proxy
Dalvik               Socket
DebugSymbol          Stalker
File                 Thread
Frida                WeakRef
Instruction          clearInterval
Interceptor          clearTimeout
Memory               console
MemoryAccessMonitor  gc
Module               ptr
NULL                 recv
NativeCallback       send
NativeFunction       setInterval
NativePointer        setTimeout
ObjC
# Look at things exposed through the ObjC interface
[Local::ProcName::Calculator]-> ObjC.<TAB>
Object            implement         selector
available         mainQueue         selectorAsString
classes           schedule
# List the first 10 classes (there are a lot of them!)
[Local::...::Calculator]-> Object.keys(ObjC.classes).slice(0, 10)
[
    "NSDrawer",
    "GEOPDETAFilter",
    "NSDeserializer",
    "CBMutableCharacteristic",
    "NSOrthographyCheckingResult",
    "DDVariable",
    "GEOVoltaireLocationShiftProvider",
    "LSDocumentProxy",
    "NSPreferencesModule",
    "CIQRCodeGenerator"
]
```

## Loading a script
```
# Connect Frida to a locally-running Calculator.app and load calc.js
$ frida Calculator -l calc.js

# The code in calc.js has now been loaded and executed. Any changes will be reloaded automatically
[Local::ProcName::Calculator]->

# Manually reload it from file at any time
[Local::ProcName::Calculator]-> %reload
[Local::ProcName::Calculator]->
```

## Enable the Node.js compatible debugger
```
# Connect Frida to a locally-running Calculator.app
# and load calc.js with the debugger enabled
$ frida Calculator -l calc.js --debug

Debugger listening on port 5858
# We can now run node-inspector and start debugging calc.js
[Local::ProcName::Calculator]->
```

[Back](https://frida.re/docs/examples/javascript/)
[Next](https://frida.re/docs/frida-ps/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
