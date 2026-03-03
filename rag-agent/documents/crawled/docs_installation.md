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
  * [](https://frida.re/docs/installation/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/installation.md)
# Installation
Getting Frida installed and ready-to-go should only take a few minutes. If it ever becomes a pain in the ass, please [file an issue](https://github.com/frida/frida-website/issues/new) (or submit a pull request) describing the issue you encountered and how we might make the process easier.
### Requirements for Frida’s CLI tools
Installing Frida’s CLI tools is easy and straight-forward, but there are a few requirements you’ll need to make sure your system has before you start.
  * [Python](https://python.org/) – latest 3.x is highly recommended
  * Windows, macOS, or GNU/Linux


## Install with pip
The best way to install Frida’s CLI tools is via [PyPI](https://pypi.python.org/pypi/frida-tools):
```
$ pip install frida-tools
```

If you have problems installing Frida, check out the [troubleshooting](https://frida.re/docs/troubleshooting/) page or [report an issue](https://github.com/frida/frida-website/issues/new) so the Frida community can improve the experience for everyone.
## Install manually
You can also grab other binaries from Frida’s GitHub [releases](https://github.com/frida/frida/releases) page.
## Testing your installation
Start a process we can inject into:
```
$ cat
```

Just let it sit and wait for input. On Windows you might want to use `notepad.exe`.
Note that this example won’t work on macOS El Capitan and later, as it rejects such attempts for system binaries. See [here](https://github.com/frida/frida/issues/83) for more details. However, if you copy the `cat` binary to e.g., `/tmp/cat` then run that instead the example should work:
```
$ cp /bin/cat /tmp/cat
$ /tmp/cat
```

In another terminal, make a file `example.py` with the following contents:
```
import frida

def on_message(message, data):
    print("[on_message] message:", message, "data:", data)

session = frida.attach("cat")

script = session.create_script("""
rpc.exports.enumerateModules = () => {
  return Process.enumerateModules();
};
""")
script.on("message", on_message)
script.load()

print([m["name"] for m in script.exports_sync.enumerate_modules()])
```

If you are on GNU/Linux, issue:
```
$ sudo sysctl kernel.yama.ptrace_scope=0
```

to enable ptracing non-child processes.
At this point, we are ready to take Frida for a spin! Run the example.py script and watch the magic:
```
$ python example.py
```

The output should be something similar to this (depending on your platform and library versions):
```
['cat', …, 'ld-2.15.so']
```

[Back](https://frida.re/docs/quickstart/)
[Next](https://frida.re/docs/modes/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
