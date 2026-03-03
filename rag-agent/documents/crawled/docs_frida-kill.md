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
  * [](https://frida.re/docs/frida-kill/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/frida-kill.md)
# frida-kill
This is a command-line tool for killing processes.
You can acquire PIDs from [frida-ps](https://frida.re/docs/frida-ps/) tool.
```
$ frida-kill -D <DEVICE-ID> <PID>
# List active applications
$ frida-ps -D 1d07b5f6a7a72552aca8ab0e6b706f3f3958f63e  -a

PID  Name                Identifier
----  ------------------  -----------------------------------------------------
4433  Camera              com.apple.camera
4001  Cydia               com.saurik.Cydia
4997  Filza               com.tigisoftware.Filza
4130  IPA Installer       com.slugrail.ipainstaller
3992  Mail                com.apple.mobilemail
4888  Maps                com.apple.Maps
6494  Messages            com.apple.MobileSMS
5029 Safari              com.apple.mobilesafari
4121  Settings            com.apple.Preferences

# Connect Frida to the device and kill running process
$ frida-kill -D 1d07b5f6a7a72552aca8ab0e6b706f3f3958f63e 5029

# Check if process has been killed
$ frida-ps -D 1d07b5f6a7a72552aca8ab0e6b706f3f3958f63e  -a

PID  Name                Identifier
----  ------------------  -----------------------------------------------------
4433  Camera              com.apple.camera
4001  Cydia               com.saurik.Cydia
4997  Filza               com.tigisoftware.Filza
4130  IPA Installer       com.slugrail.ipainstaller
3992  Mail                com.apple.mobilemail
4888  Maps                com.apple.Maps
6494  Messages            com.apple.MobileSMS
4121  Settings            com.apple.Preferences
```

[Back](https://frida.re/docs/frida-ls-devices/)
[Next](https://frida.re/docs/gum-graft/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
