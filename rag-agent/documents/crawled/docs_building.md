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
  * [](https://frida.re/docs/building/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/building.md)
# Building
## Table of contents
  1. Building Frida 
     * [Prerequisites](https://frida.re/docs/building/#prerequisites)
     * [Getting the code](https://frida.re/docs/building/#clone)
     * [Building for the native machine](https://frida.re/docs/building/#native)
     * [Building for a different machine](https://frida.re/docs/building/#cross)
     * [Building out-of-tree](https://frida.re/docs/building/#oot)


## Building Frida
### Prerequisites
You need:
  * C/C++ toolchain
  * Node.js >= 18
  * Git


For example on an Ubuntu system:
```
$ sudo apt-get install build-essential git lib32stdc++-9-dev \
    libc6-dev-i386 nodejs npm
```

### Getting the code
```
$ git clone https://github.com/frida/frida.git
```

### Building for the native machine
To build, run:
```
$ make
```

Which will use `./build` as the build directory. Run `make install` to install.
You may also do `./configure` first to specify a `--prefix`, or any other options. Use `--help` to list the top-level options.
For setting lower level options, do:
```
$ ./configure -- first-option second-option …
```

The options after `--` are passed directly to Meson’s `setup` command. This means you can also pass project options to subprojects, e.g.:
```
$ ./configure -- \
    -Dfrida-gum:devkits=gum,gumjs \
    -Dfrida-core:devkits=core
```

Consult `meson.options` in subprojects/* for available options. You may also clone the different repos standalone and build the same way as described here.
### Building for a different machine
#### iOS/watchOS/tvOS
```
$ ./configure --host=ios-arm64
# or: ./configure --host=watchos-arm64
# or: ./configure --host=tvos-arm64
# optionally suffixed by `-simulator`
$ make
```

#### Android
```
$ ./configure --host=android-arm64
$ make
```

#### Raspberry Pi
```
$ sudo apt-get install g++-arm-linux-gnueabihf
$ ./configure --host=arm-linux-gnueabihf
$ make
```

### Building out-of-tree
Sometimes you may want to use a single source tree to build for multiple systems or configurations. To do this, invoke `configure` from an empty directory outside the source tree:
```
$ mkdir build-ios
$ ../frida/configure --host=ios-arm64
$ make
$ cd ..
$ mkdir build-android
$ ../frida/configure --host=android-arm64
$ make
```

[Back](https://frida.re/docs/troubleshooting/)
[Next](https://frida.re/docs/footprint/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
