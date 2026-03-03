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
  * [](https://frida.re/docs/ios/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/ios.md)
# iOS
Frida supports two modes of operation, depending on whether your iOS device is jailbroken or not.
## Table of contents
  1. [With Jailbreak](https://frida.re/docs/ios/#with-jailbreak)
  2. [Without Jailbreak](https://frida.re/docs/ios/#without-jailbreak)


## With Jailbreak
This is the most powerful setup, as it lets you instrument system services and apps with very little effort.
In this tutorial we will show you how to do function tracing on your iOS device.
### Setting up your iOS device
Start `Cydia` and add Frida’s repository by going to `Manage` -> `Sources` -> `Edit` -> `Add` and enter `https://build.frida.re`. You should now be able to find and install the `Frida` package which lets Frida inject JavaScript into apps running on your iOS device. This happens over USB, so you will need to have your USB cable handy, though there’s no need to plug it in just yet.
### A quick smoke-test
Now, back on your Windows or macOS system it’s time to make sure the basics are working. Run:
```
$ frida-ps -U
```

##### Using a Linux-based OS?
As of Frida 6.0.9 there's now usbmuxd integration, so -U works. For earlier Frida versions you can use WiFi and set up an SSH tunnel between localhost:27042 on both ends, and then use -R instead of -U. 
Unless you already plugged in your device, you should see the following message:
```
Waiting for USB device to appear...
```

Plug in your device, and you should see a process list along the lines of:
```
 PID NAME
 488 Clock
 116 Facebook
 312 IRCCloud
1711 LinkedIn
…
```

Great, we’re good to go then!
### Tracing crypto calls in the Twitter app
Alright, let’s have some fun. Fire up the Twitter app on your device, and while making sure it stays in the foreground without the device going to sleep, go back to your desktop and run:
```
$ frida-trace -U -i "CCCryptorCreate*" Twitter
Uploading data...
CCCryptorCreate: Auto-generated handler …/CCCryptorCreate.js
CCCryptorCreateFromData: Auto-generated handler …/CCCryptorCreateFromData.js
CCCryptorCreateWithMode: Auto-generated handler …/CCCryptorCreateWithMode.js
CCCryptorCreateFromDataWithMode: Auto-generated handler …/CCCryptorCreateFromDataWithMode.js
Started tracing 4 functions. Press Ctrl+C to stop.
```

Now, `CCryptorCreate` and friends are part of Apple’s `libcommonCrypt.dylib`, and is used by many apps to take care of encryption, decryption, hashing, etc.
Reload your Twitter feed or exercise the UI in some way that results in network traffic, and you should see some output like the following:
```
3979 ms	CCCryptorCreate()
3982 ms	CCCryptorCreateWithMode()
3983 ms	CCCryptorCreate()
3983 ms	CCCryptorCreateWithMode()
```

You can now live-edit the aforementioned JavaScript files as you read `man CCryptorCreate`, and start diving deeper and deeper into your iOS apps.
## Without Jailbreak
Frida is able to instrument debuggable apps, and will inject [Gadget](https://frida.re/docs/gadget/) automatically as of Frida 12.7.12.
Only a few requirements to be aware of:
  * The iOS device should ideally be running iOS 13 or newer. Support for older versions is considered experimental.
  * The Developer Disk Image must be mounted. Xcode will mount it automatically as soon as it discovers the iOS USB device, but you can also do it manually by using _ideviceimagemounter_.
  * Latest Gadget must be present in the user’s cache directory. On macOS this is `~/.cache/frida/gadget-ios.dylib`, but you can figure out the exact path by attempting to attach to a debuggable app and then reading the error message.


## Building your own tools
While the CLI tools like _frida_ , _frida-trace_ , etc., are definitely quite useful, there might be times when you’d like to build your own tools harnessing the powerful [Frida APIs](https://frida.re/docs/javascript-api/). For that we would recommend reading the chapters on [Functions](https://frida.re/docs/functions) and [Messages](https://frida.re/docs/functions), and anywhere you see `frida.attach()` just substitute that with `frida.get_usb_device().attach()`.
[Back](https://frida.re/docs/messages/)
[Next](https://frida.re/docs/android/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
