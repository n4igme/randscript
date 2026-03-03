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
  * [](https://frida.re/docs/troubleshooting/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/troubleshooting.md)
# Troubleshooting
If you ever run into problems installing or using Frida, here’s a few tips that might be of help. If the problem you’re experiencing isn’t covered below, please [report an issue](https://github.com/frida/frida-website/issues/new) so the Frida community can make everyone’s experience better.
## ValueError: ambiguous name; it matches:
This means the process name you specified in `frida.attach()` matches more than one process. You can use the PID instead:
```
session = frida.attach(12345)
```

## SystemError: attach_to_process PTRACE_ATTACH failed: 1
This (probably) means that you don’t have permissions to attach to the target process. The process may be owned by another user and you are not root. You may have forgotten to enable ptrace of non-child processes. Try:
```
sudo sysctl kernel.yama.ptrace_scope=0
```

This could also be [due to Magisk Hide](https://github.com/frida/frida/issues/824#issuecomment-479664290). Try disabling it and rebooting before running your command.
## Failed to spawn: unexpected error while spawning child process ‘XXX’ (task_for_pid returned ‘(os/kern) failure’)
On macOS this probably means that you didn’t properly sign Frida or that there is a permission missing. For example if you are running Frida over SSH and can’t respond to the authentication dialog that would pop up under _normal_ use.
If it’s a signature problem, follow [this procedure](https://github.com/frida/frida#mac-and-ios) else, try:
```
**WARNING: This may weaken security**
sudo security authorizationdb write system.privilege.taskport allow
```

You also may have to disable System Integrity Protection to instrument system binaries but, again, _*/!\ this WILL weaken security /!*_.
## ImportError: dynamic module does not define init function (init_frida)
This or another similar error message is seen when trying to use `frida-python` compiled for python 2.x in python 3.x, or vice versa. Check which python interpreter you are running against which `PYTHONPATH` / `sys.path` is used.
[Back](https://frida.re/docs/best-practices/)
[Next](https://frida.re/docs/building/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
