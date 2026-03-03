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
  * [](https://frida.re/docs/android/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/android.md)
# Android
In this tutorial we show how to do function tracing on your Android device.
## Setting up your Android device
Before you start, you will need to root your device in case you haven’t done so already. It is technically also possible to use Frida without rooting your device, for example by repackaging the app to include frida-gadget, or using a debugger to accomplish the same. But, for this introduction we’re going to focus on the simplest case: a rooted device.
Also note that most of our recent testing has been taking place on a Pixel 3 running Android 9. Older ROMs may work too, but if you’re running into basic issues like Frida crashing the system when launching an app, this is due to ROM-specific quirks. We cannot test on all possible devices, so we count on your help to improve on this. However if you’re just starting out with Frida it is strongly recommended to go for a Pixel or Nexus device running the latest official software, or a device whose software is as close to AOSP as possible. Another option is using an emulator, ideally with a Google-provided Android 9 emulator image for arm or arm64. (x86 may work too but has gone through significantly less testing.)
You will also need the `adb` tool from the Android SDK.
First off, download the latest `frida-server` for Android from our [releases page](https://github.com/frida/frida/releases) and uncompress it.
```
$ adb shell getprop ro.product.cpu.abilist # check your device cpu type

$ unxz frida-server.xz
```

Now, let’s get it running on your device:
```
$ adb root # might be required
$ adb push frida-server /data/local/tmp/
$ adb shell "chmod 755 /data/local/tmp/frida-server"
$ adb shell "/data/local/tmp/frida-server &"
```

Some apps might be able to detect the frida-server location. Renaming the frida-server binary to a random name, or moving it to another location such as /dev may do the trick.
For the last step, make sure you start frida-server as root, i.e. if you are doing this on a rooted device, you might need to _su_ and run it from that shell.
##### adb on a production build
If you get `adbd cannot run as root in production builds` after running `adb root`  
you need to prefix each shell command with `su -c`. For example: `adb shell "su -c chmod 755 /data/local/tmp/frida-server"`
Next, make sure `adb` can see your device:
```
$ adb devices -l
```

This will also ensure that the adb daemon is running on your desktop, which allows Frida to discover and communicate with your device regardless of whether you’ve got it hooked up through USB or WiFi.
## A quick smoke-test
Now, on your desktop it’s time to make sure the basics are working. Run:
```
$ frida-ps -U
```

This should give you a process list along the lines of:
```
  PID NAME
 1590 com.facebook.katana
13194 com.facebook.katana:providers
12326 com.facebook.orca
13282 com.twitter.android
…
```

Great, we’re good to go then!
## Tracing open() calls in Chrome
Alright, let’s have some fun. Fire up the Chrome app on your device and return to your desktop and run:
```
$ frida-trace -U -i open -N com.android.chrome
Uploading data...
open: Auto-generated handler …/linker/open.js
open: Auto-generated handler …/libc.so/open.js
Started tracing 2 functions. Press Ctrl+C to stop.
```

Now just play around with the Chrome app and you should start seeing `open()` calls flying in:
```
1392 ms	open()
1403 ms	open()
1420 ms	open()
```

You can now live-edit the aforementioned JavaScript files as you read `man open`, and start diving deeper and deeper into your Android apps.
## Building your own tools
While the CLI tools like _frida_ , _frida-trace_ , etc., are definitely quite useful, there might be times when you’d like to build your own tools harnessing the powerful [Frida APIs](https://frida.re/docs/javascript-api/). For that we would recommend reading the chapters on [Functions](https://frida.re/docs/functions) and [Messages](https://frida.re/docs/messages), and anywhere you see `frida.attach()` just substitute that with `frida.get_usb_device().attach()`.
[Back](https://frida.re/docs/ios/)
[Next](https://frida.re/docs/examples/windows/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
