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
  * [](https://frida.re/docs/bridges/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/bridges.md)
# Bridges
Starting with Frida 17.0.0, bridges are no longer bundled with Frida’s GumJS runtime. You can read more about it in the [release notes](https://frida.re/news/2025/05/17/frida-17-0-0-released/). This means that users now have to explicitly pull in the bridges they want to use. The Frida REPL and `frida-trace` do however come with all three bridges bundled, for compatibility with existing scripts.
## Table of contents
  1. **REPL and frida-trace**
    1. [Using plain JavaScript](https://frida.re/docs/bridges/#using-plain-javascript)
    2. [REPL automatic compilation](https://frida.re/docs/bridges/#repl-automatic-compilation)
    3. [Manually compiling using frida-compile](https://frida.re/docs/bridges/#manually-compiling-using-frida-compile)
  2. **Using API**
    1. [Python example](https://frida.re/docs/bridges/#python-example)
    2. [Go example](https://frida.re/docs/bridges/#go-example)


## REPL and frida-trace
We will use a simple script to print `ObjC.available` to the screen.
```
// script.js
console.log(ObjC.available);
```

### Using plain JavaScript
This works exactly like before since REPL and frida-trace have all three bridges bundled.
```
$ frida -p0 -l script.js
     ____
    / _  |   Frida 17.0.5 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Attaching...
true
[Local::SystemSession ]->
```

### REPL automatic compilation
The REPL can also work with `.ts` files: use `frida-create -t agent` in an empty directory to set up the needed scaffolding.
### Manually compiling using frida-compile
You need to specify which bridges you want to use (ObjC, Java, Swift) by adding lines inside your script:
  * `import ObjC from "frida-objc-bridge";` - for ObjC
  * `import Swift from "frida-swift-bridge";` - for Swift
  * `import Java from "frida-java-bridge";` - for Java


We will recreate the example above where we used plain JavaScript to print `ObjC.available`.
```
// script.ts
import ObjC from "frida-objc-bridge";

console.log(ObjC.available);
```

Initialize and install necessary packages in an empty directory:
```
$ frida-create -t agent
$ npm install
$ npm install frida-objc-bridge
```

Then compile the agent and load it:
```
$ frida-compile script.ts -o _agent.js -S -c
$ frida -p0 -l _agent.js
     ____
    / _  |   Frida 17.0.5 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Attaching...
true
[Local::SystemSession ]->
```

## Using API
There are a few steps needed to do it using APIs provided by bindings, which are:
  * Write the script
  * Run `frida-create -t agent`
  * Install bridge(s) you want, e.g. `frida-objc-bridge`
  * Write the code to compile the script and load it in the process


### Python example
```
import frida

def on_diagnostics(diag):
    print("diag", diag)

def on_message(message, data):
    print(message)

compiler = frida.Compiler()
compiler.on("diagnostics", on_diagnostics)
# script is located in /tmp, so we set project root to /tmp
bundle = compiler.build("script.ts", project_root="/tmp")

session = frida.attach(0)

script = session.create_script(bundle)

script.on("message", on_message)
script.load()
```

### Go example
```
package main

import (
	"bufio"
	"fmt"
	"github.com/frida/frida-go/frida"
	"os"
)

func main() {
	comp := frida.NewCompiler()
	comp.On("diagnostics", func(diag string) {
		fmt.Printf("Diagnostics: %s\n", diag)
	})

	bopts := frida.NewCompilerOptions()
	bopts.SetProjectRoot("/tmp")
	bopts.SetSourceMaps(frida.SourceMapsOmitted)
	bopts.SetJSCompression(frida.JSCompressionTerser)

	bundle, err := comp.Build("script.ts", bopts)
	if err != nil {
		panic(err)
	}

	session, err := frida.Attach(0)
	if err != nil {
		panic(err)
	}

	script, err := session.CreateScript(bundle)
	if err != nil {
		panic(err)
	}

	script.On("message", func(message string, data []byte) {
		fmt.Printf("%s\n", message)
	})

	script.Load()

	r := bufio.NewReader(os.Stdin)
	r.ReadLine()
}
```

[Back](https://frida.re/docs/go-api/)
[Next](https://frida.re/docs/best-practices/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
