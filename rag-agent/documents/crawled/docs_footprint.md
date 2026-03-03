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
  * [](https://frida.re/docs/footprint/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/footprint.md)
# Footprint
We put a lot of effort into making sure that Frida can scale from desktops all the way down to embedded systems.
While our prebuilt binaries ship with all features enabled, building Frida yourself means you can tailor it to your needs and build significantly smaller binaries. The way this is done is by tweaking the available options in `config.mk`:
```
# Features ordered by binary footprint, from largest to smallest
FRIDA_V8 ?= enabled
FRIDA_CONNECTIVITY ?= enabled
FRIDA_DATABASE ?= enabled
FRIDA_JAVA_BRIDGE ?= auto
FRIDA_OBJC_BRIDGE ?= auto
FRIDA_SWIFT_BRIDGE ?= auto
```

If working on embedded systems, all the aforementioned features may be disabled.
Specifically, they are only required in the following cases:
  * FRIDA_V8: default Javascript runtime is QuickJS so it can safely disabled if not used. Required if the V8 runtime is needed, for example when specifically requested via the API `create_script(..., runtime='v8')` or through the frida-tools CLI with `--runtime=v8`.
  * FRIDA_CONNECTIVITY: required if using certificates to enable TLS, or if using `setup_peer_connection()` (API) or `--p2p` (CLI). Note that it is not required for network connectivity. For example, it is not required when using frida-server like this: `frida-server -l 0.0.0.0`.
  * FRIDA_DATABASE: required if using [SqliteDatabase](https://frida.re/docs/javascript-api/#sqlitedatabase) and related APIs, can be safely disabled if not.
  * FRIDA_JAVA_BRIDGE: required when wanting to call or instrument Java APIs inside processes with a Java Virtual Machine or Android Runtime environment. Note that there are other languages apart from Java which run either on the JVM or the Android Runtime, such as Kotlin and Scala.
  * FRIDA_OBJC_BRIDGE and FRIDA_SWIFT_BRIDGE: required when wanting to call or instrument Objective-C or Swift code. Useful on Apple OSes, like i/macOS, may be safely disabled outside the Apple ecosystem.


Let’s run through these and look at how the different options impact footprint size on Linux/armhf (32-bit ARM).
To make the following a bit clearer, we have added `-Dassets=installed` to the frida-core Meson options. This means that frida-agent.so is not embedded into the frida-server/frida-inject binary, but is instead loaded from the filesystem.
This is also what you typically want on embedded systems, as writing out the agent to /tmp is somewhat wasteful, whether it’s backed by flash or tmpfs.
## All config.mk features enabled on linux-armhf
```
3.8M frida-inject
3.2M frida-server
 15M frida-agent.so
 15M frida-gadget.so
```

## Step 1: Disable V8
```
3.8M frida-inject
3.2M frida-server
5.2M frida-agent.so
5.3M frida-gadget.so
```

Agent reduced by 9.8M.
## Step 2: Disable connectivity features (TLS and ICE), eliminating OpenSSL
```
2.6M frida-inject
2.0M frida-server
3.6M frida-agent.so
3.7M frida-gadget.so
```

Agent reduced by 1.6M.
## Step 3: Disable the GumJS Database API, eliminating SQLite
```
2.6M frida-inject
2.0M frida-server
3.2M frida-agent.so
3.3M frida-gadget.so
```

Agent reduced by 0.4M.
## Step 4: Disable the GumJS bridges: ObjC, Swift, Java
```
2.6M frida-inject
2.0M frida-server
2.8M frida-agent.so
2.9M frida-gadget.so
```

Agent reduced by 0.4M.
Let’s look at what we’re left with:
![frida-agent.so footprint](https://frida.re/img/frida-agent-footprint.png)
And to sate our curiosity, let’s have a closer look at three of the components that stand out:
![libcapstone.a footprint](https://frida.re/img/capstone-breakdown.png)
![libglib-2.0.a footprint](https://frida.re/img/glib-breakdown.png)
![libgio-2.0.a footprint](https://frida.re/img/gio-breakdown.png)
[Back](https://frida.re/docs/building/)
[Next](https://frida.re/docs/contributing/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
