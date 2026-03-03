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
  * [](https://frida.re/docs/home/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/index.md)
# Welcome
This site aims to be a comprehensive guide to Frida. We’ll cover topics such as doing interactive function tracing from the command-line, building your own tools on top of Frida’s APIs, and give you some advice on participating in the future development of Frida itself.
## So what is Frida, exactly?
It’s [Greasemonkey](https://addons.mozilla.org/en-US/firefox/addon/greasemonkey/) for native apps, or, put in more technical terms, it’s a dynamic code instrumentation toolkit. It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, watchOS, tvOS, Android, FreeBSD, and QNX. Frida also provides you with some simple tools built on top of the Frida API. These can be used as-is, tweaked to your needs, or serve as examples of how to use the API.
## Why do I need this?
Great question. We’ll try to clarify with some use-cases:
  * There’s this new hot app everybody’s so excited about, but it’s only available for iOS and you’d love to interop with it. You realize it’s relying on encrypted network protocols and tools like Wireshark just won’t cut it. You pick up Frida and use it for API tracing.
  * You’re building a desktop app which has been deployed at a customer’s site. There’s a problem but the built-in logging code just isn’t enough. You need to send your customer a custom build with lots of expensive logging code. Then you realize you could just use Frida and build an application- specific tool that will add all the diagnostics you need, and in just a few lines of Python. No need to send the customer a new custom build - you just send the tool which will work on many versions of your app.
  * You’d like to build a Wireshark on steroids with support for sniffing encrypted protocols. It could even manipulate function calls to fake network conditions that would otherwise require you to set up a test lab.
  * Your in-house app could use some black-box tests without polluting your production code with logic only required for exotic testing.


## Why a Python API, but JavaScript debugging logic?
Frida’s core is written in C and injects [QuickJS](https://bellard.org/quickjs/) into the target processes, where your JS gets executed with full access to memory, hooking functions and even calling native functions inside the process. There’s a bi-directional communication channel that is used to talk between your app and the JS running inside the target process.
Using Python and JS allows for quick development with a risk-free API. Frida can help you easily catch errors in JS and provide you an exception rather than crashing.
Rather not write in Python? No problem. You can use Frida from C directly, and on top of this C core there are multiple language bindings, e.g. [Node.js](https://github.com/frida/frida-node), [Python](https://github.com/frida/frida-python), [Swift](https://github.com/frida/frida-swift), [.NET](https://github.com/frida/frida-clr), [Qml](https://github.com/frida/frida-qml), [Go](https://github.com/frida/frida-go), etc. It is very easy to build additional bindings for other languages and environments.
## ProTips™, Notes, and Warnings
Throughout this guide there are a number of small-but-handy pieces of information that can make using Frida easier, more interesting, and less hazardous. Here’s what to look out for.
##### ProTips™ help you get more from Frida
These are tips and tricks that will help you be a Frida wizard!
##### Notes are handy pieces of information
These are for the extra tidbits sometimes necessary to understand Frida.
##### Warnings help you not blow things up
Be aware of these messages if you wish to avoid certain death.
If you come across anything along the way that we haven’t covered, or if you know of a tip you think others would find handy, please [file an issue](https://github.com/frida/frida-website/issues/new), and we’ll see about including it in this guide.
Back
[Next](https://frida.re/docs/quickstart/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
