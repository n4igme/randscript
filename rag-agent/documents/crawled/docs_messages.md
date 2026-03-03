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
  * [](https://frida.re/docs/messages/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/messages.md)
# Messages
In this tutorial we show how to send messages to and from a target process.
## Setting up the experiment
Create a file `hello.c`:
```
#include <stdio.h>
#include <unistd.h>

void
f (int n)
{
  printf ("Number: %d\n", n);
}

int
main (int argc,
      char * argv[])
{
  int i = 0;

  printf ("f() is at %p\n", f);

  while (1)
  {
    f (i++);
    sleep (1);
  }
}
```

Compile with:
```
$ gcc -Wall hello.c -o hello
```

Start the program and make note of the address of `f()` (`0x400544` in the following example):
```
f() is at 0x400544
Number: 0
Number: 1
Number: 2
…
```

## Sending messages from a target process
The following script shows how to send a message back to the Python process. You can send any JavaScript value which is serializable to JSON.
Create a file `send.py` containing:
```
import frida
import sys

session = frida.attach("hello")
script = session.create_script("send(1337);")
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

When you run this script:
```
$ python send.py
```

it should print the following message:
```
{'type': 'send', 'payload': 1337}
```

This means that the JavaScript code `send(1337)` has been executed inside the `hello` process. Terminate the script with `Ctrl-D`.
### Handling runtime errors from JavaScript
If the JavaScript script throws an uncaught exception, this will be propagated from the target process into the Python script. If you replace `send(1337)` with `send(a)` (an undefined variable), the following message will be received by Python:
```
{'type': 'error', 'description': 'ReferenceError: a is not defined', 'lineNumber': 1}
```

Note the `type` field (`error` vs `send`).
## Receiving messages in a target process
It is possible to send messages from the Python script to the JavaScript script. Create the file `pingpong.py`:
```
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
    recv('poke', function onMessage(pokeMessage) { send('pokeBack'); });
""")
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
script.post({"type": "poke"})
sys.stdin.read()
```

Running the script:
```
$ python pingpong.py
```

produces the output:
```
{'type': 'send', 'payload': 'pokeBack'}
```

##### The mechanics of recv()
The recv() method itself is async (non-blocking). The registered callback (onMessage) will receive exactly one message. To receive the next message, the callback must be reregistered with recv(). 
### Blocking receives in the target process
It is possible to wait for a message to arrive (a blocking receive) inside your JavaScript script. Create a script `rpc.py`:
```
import frida
import sys

session = frida.attach("hello")
script = session.create_script("""
Interceptor.attach(ptr("%s"), {
    onEnter(args) {
        send(args[0].toString());
        const op = recv('input', value => {
            args[0] = ptr(value.payload);
        });
        op.wait();
    }
});
""" % int(sys.argv[1], 16))
def on_message(message, data):
    print(message)
    val = int(message['payload'], 16)
    script.post({'type': 'input', 'payload': str(val * 2)})
script.on('message', on_message)
script.load()
sys.stdin.read()
```

The program `hello` should be running, and you should make a note of the address printed at its beginning (e.g. `0x400544`). Run:
```
$ python rpc.py 0x400544
```

then observe the change in the terminal where `hello` is running:
```
Number: 3
Number: 8
Number: 10
Number: 12
Number: 14
Number: 16
Number: 18
Number: 20
Number: 22
Number: 24
Number: 26
Number: 14
```

The `hello` program should start writing “doubled” values until you stop the Python script (`Ctrl-D`).
[Back](https://frida.re/docs/functions/)
[Next](https://frida.re/docs/ios/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
