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
  * [](https://frida.re/docs/frida-trace/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/frida-trace.md)
# frida-trace
frida-trace is a tool for dynamically tracing function calls.
```
# Trace recv* and send* APIs in Safari, insert library names
# in logging
$ frida-trace --decorate -i "recv*" -i "send*" Safari

# Trace ObjC method calls in Safari
$ frida-trace -m "-[NSView drawRect:]" Safari

# Launch SnapChat on your iPhone and trace crypto API calls
$ frida-trace \
    -U \
    -f com.toyopagroup.picaboo \
    -I "libcommonCrypto*"

# Launch YouTube on your Android device and trace Java methods
# with “certificate” in their signature (s), ignoring case (i)
# and only searching in user-defined classes (u)
$ frida-trace \
    -U \
    -f com.google.android.youtube \
    --runtime=v8 \
    -j '*!*certificate*/isu'

# Trace all JNI functions in Samsung FaceService app on Android
$ frida-trace -U -i "Java_*" com.samsung.faceservice

# Trace a Windows process's calls to "mem*" functions in msvcrt.dll
$ frida-trace -p 1372 -i "msvcrt.dll!*mem*"

# Trace all functions matching "*open*" in the process except
# in msvcrt.dll
$ frida-trace -p 1372 -i "*open*" -x "msvcrt.dll!*open*"

# Trace an unexported function in libjpeg.so
$ frida-trace -p 1372 -a "libjpeg.so!0x4793c"
```

## Full List of Options
```
$ frida-trace -h
usage: frida-trace [options] target

positional arguments:
  args                  extra arguments and/or target

options:
  -h, --help            show this help message and exit
  -D ID, --device ID    connect to device with the given ID
  -U, --usb             connect to USB device
  -R, --remote          connect to remote frida-server
  -H HOST, --host HOST  connect to remote frida-server on HOST
  --certificate CERTIFICATE
                        speak TLS with HOST, expecting CERTIFICATE
  --origin ORIGIN       connect to remote server with “Origin” header set to ORIGIN
  --token TOKEN         authenticate with HOST using TOKEN
  --keepalive-interval INTERVAL
                        set keepalive interval in seconds, or 0 to disable (defaults to -1 to auto-select based on transport)
  --p2p                 establish a peer-to-peer connection with target
  --stun-server ADDRESS
                        set STUN server ADDRESS to use with --p2p
  --relay address,username,password,turn-{udp,tcp,tls}
                        add relay to use with --p2p
  -f TARGET, --file TARGET
                        spawn FILE
  -F, --attach-frontmost
                        attach to frontmost application
  -n NAME, --attach-name NAME
                        attach to NAME
  -N IDENTIFIER, --attach-identifier IDENTIFIER
                        attach to IDENTIFIER
  -p PID, --attach-pid PID
                        attach to PID
  -W PATTERN, --await PATTERN
                        await spawn matching PATTERN
  --stdio {inherit,pipe}
                        stdio behavior when spawning (defaults to “inherit”)
  --aux option          set aux option when spawning, such as “uid=(int)42” (supported types are: string, bool, int)
  --realm {native,emulated}
                        realm to attach in
  --runtime {qjs,v8}    script runtime to use
  --debug               enable the Node.js compatible script debugger
  --squelch-crash       if enabled, will not dump crash report to console
  -O FILE, --options-file FILE
                        text file containing additional command line options
  --version             show program's version number and exit
  -I MODULE, --include-module MODULE
                        include MODULE
  -X MODULE, --exclude-module MODULE
                        exclude MODULE
  -i FUNCTION, --include FUNCTION
                        include [MODULE!]FUNCTION
  -x FUNCTION, --exclude FUNCTION
                        exclude [MODULE!]FUNCTION
  -a MODULE!OFFSET, --add MODULE!OFFSET
                        add MODULE!OFFSET
  -T INCLUDE_IMPORTS, --include-imports INCLUDE_IMPORTS
                        include program's imports
  -t MODULE, --include-module-imports MODULE
                        include MODULE imports
  -m OBJC_METHOD, --include-objc-method OBJC_METHOD
                        include OBJC_METHOD
  -M OBJC_METHOD, --exclude-objc-method OBJC_METHOD
                        exclude OBJC_METHOD
  -y SWIFT_FUNC, --include-swift-func SWIFT_FUNC
                        include SWIFT_FUNC
  -Y SWIFT_FUNC, --exclude-swift-func SWIFT_FUNC
                        exclude SWIFT_FUNC
  -j JAVA_METHOD, --include-java-method JAVA_METHOD
                        include JAVA_METHOD
  -J JAVA_METHOD, --exclude-java-method JAVA_METHOD
                        exclude JAVA_METHOD
  -s DEBUG_SYMBOL, --include-debug-symbol DEBUG_SYMBOL
                        include DEBUG_SYMBOL
  -q, --quiet           do not format output messages
  -d, --decorate        add module name to generated onEnter log statement
  -S PATH, --init-session PATH
                        path to JavaScript file used to initialize the session
  -P PARAMETERS_JSON, --parameters PARAMETERS_JSON
                        parameters as JSON, exposed as a global named 'parameters'
  -o OUTPUT, --output OUTPUT
                        dump messages to file
  --ui-port UI_PORT     the TCP port to serve the UI on
```

## -U, –usb: connect to USB device
This option tells `frida-trace` to perform tracing on a remote device connected via the host machine’s USB connection.
Example: You want to trace an application running on an Android device from your host Windows machine. If you specify `-U / --usb`, frida-trace will perform the necessary work to transfer all data to and from the remote device and trace accordingly.
##### Copy frida-server binary to remote device
When tracing a remote device, remember to copy the [platform-appropriate frida-server binary](https://github.com/frida/frida/releases) to the remote device. Once copied, be sure to run the frida-server binary before beginning the tracing session.
For example, to trace a remote Android application, you might copy the 'frida-server-12.8.0-android-arm' binary to the Android's /data/local/tmp folder. Using adb shell, you would run the server in the background (e.g. "frida-server-12.8.0-android-arm &").
## -O: pass command line options via text file
Using this option, you can pass any number of command line options via one or more text files. The options in the text file can be on one or more lines, with any number of options per line, including other `-O` command options.
This feature is useful for handling a large number of command line options, and solves the problem when the command line exceeds the operating system maximum command line length.
For example:
```
$ frida-trace -p 9753 --decorate -O additional-options.txt
```

where additional-options.txt is:
```
-i "gdi32full.dll!ExtTextOutW"
-S core.js -S ms-windows.js
-O module-offset-options.txt
```

and module-offset-options.txt is:
```
-a "gdi32full.dll!0x3918DC" -a "gdi32full.dll!0xBE7458"
-a "gdi32full.dll!0xBF9904"
```

## -I, -X: include/exclude module
These options allow you to include or exclude, in one single option, **all** functions in a particular module (e.g., *.so, *.dll) in one, single option. The option expects a filename glob for matching one or more modules. Any module that matches the glob pattern will be either included or excluded in its entirety.
`frida-trace` will generate a JavaScript handler file for each function matched by the `-I` option.
To exclude specific functions after including an entire module, see the `-x` option.
## -i, -x: include/exclude function (glob-based)
These options enable you to include or exclude matching functions according to your needs. These are flexible options, allowing a granularity ranging from **all** functions in **all** modules down to a single function in a specific module.
`frida-trace` will generate a JavaScript handler file for each function matched by the `-i` option.
The `-i / -x` options differ syntactically from their uppercase counterparts in that they accept any of the following forms (MODULE and FUNCTION are both glob patterns):
```
- MODULE!FUNCTION
- FUNCTION
- !FUNCTION
- MODULE!

```

Here are some examples and their descriptions:
Option Value | Description  
---|---  
-i “msvcrt.dll!_cpy_ ” | Matches all functions with ‘cpy’ in its name, ONLY in msvcrt.dll  
-i “ _free_ ” | Matches all functions with ‘free’ in its name in ALL modules  
-i “!_free_ ” | Identical to -i “ _free_ ”  
-i “gdi32.dll!” | Trace all functions in gdi32.dll (identical to -I “gdi32.dll”)  
##### frida-trace's working set and the order of inclusions and exclusions
frida-trace has an internal concept of a "working set", i.e., a set of "module:function" pairs whose handlers will be traced at runtime. The contents of the working set can be changed by an include / exclude command line option (-I / -X / -i / -x).
It is important to understand that the order of the include / exclude options is important. Each such option works on the current state of the working set, and different orderings of options can lead to different results. In other words, the include/exclude options are procedural (i.e., order counts) rather than simply declarative.
For example, suppose we want to trace all "str*" and "mem*" functions in all modules in a running process. In our example, these functions are found in three modules: _ucrtbase.dll, ntdll.dll, and msvcrt.dll_. To reduce the noise, however, we do not want to trace any functions found in the msvcrt.dll module.
We will describe three different option orders on the command line and show that they produce different results.
  * -i "str*" -i "mem*" -X "msvcrt.dll" 
    * '-i "str*"'
matches 80 functions in 3 modules, working set has 80 entries
    * '-i "mem*"'
matches 18 functions in 3 modules, working set has 98 entries
    * '-X "msvcrt.dll"'
removes the 28 "str" and 6 "mem" functions originating in msvcrt.dll, **final working set has 64 entries**.
  * -i "str*" -X "msvcrt.dll" -i "mem*" 
    * '-i "str*"'
matches 80 functions in 3 modules, working set has 80 entries
    * '-X "msvcrt.dll"'
removes the 28 "str" functions originating in msvcrt.dll, working set has 52 entries.
    * '-i "mem*"'
matches 18 functions in 3 modules including msvcrt.dll, **final working set has 70 entries**
  * -X "msvcrt.dll" -i "str*" -i "mem*" 
    * '-X "msvcrt.dll"'
tries to remove the 28 "str" and 6 "mem" functions originating in msvcrt.dll. Since the working set is empty, there is nothing to remove, working set has 0 entries.
    * '-i "str*"'
matches 80 functions in 3 modules, working set has 80 entries
    * '-i "mem*"'
matches 18 functions in 3 modules, **final working set has 98 entries**


## -a: include function (offset-based)
This option enables tracing functions whose names are not exported by their parent modules (e.g., a static C/C++ function). This should not prevent you from tracing such functions, so long as you know the absolute offset of that function’s entry point.
Example: `-a "libjpeg.so!0x4793c"`
In this example, the option’s value provides both the full name of the module (i.e., `libjpeg.so`) and the hex offset (`0x4793c`) of the function entry point within the module.
`frida-trace` will generate a JavaScript handler file for each function matched by the `-a` option.
## -P: Initialize frida-trace session with a globally-accessible JSON object
This option enables assigning a JSON object to the `parameters` global variable. Your handlers can access this global variable, enabling you to dynamically change the handlers’ behavior by modifying the value of `-P` passed on the command line.
The JSON object passed can be as complicated or extensive as you wish, so long as it is valid JSON.
##### Example
In your session, you are tracing many functions. At times you want all handlers to print out their process ID. Using the `-P` option, you can enable a handler to decide whether or not to print the process ID. 
First, decide on the JSON object format that notifies a handler whether it should display the process ID. Let's use the following format:   
  

-P '{"displayPid": true}' 
  
Note that this form is the one you might use under Linux (i.e., you can use both single- and double-quotes on the command line). Under Windows you can only use double quotes, so you should escape the inner double quotes by inserting **two** double quotes, like this:   
  

-P "{""displayPid"": true}" 
  
Frida-trace will assign your JSON object to the global JavaScript variable "_parameters_ ". Now, your handler can check the parameters.displayPid variable to decide whether to print the process ID:   
  
`{   onEnter(log, args, state) {     log('memcpy() [msvcrt.dll]');     if (parameters.displayPid) {       log(`Process ID: ${Process.id}`);     }   },    onLeave(log, retval, state) {   } } `   

## -S: Initialize frida-trace session with JavaScript code
This option initializes your frida-trace session by executing one or more JavaScript code files of your choice, which may declare globally visible functions and add arbitrary data to the global “state” object. When the “state” object is passed to any of your handlers, you have immediate access to anything you saved to it during session initialization.
Uses of this powerful feature include initializing the frida-trace running environment before the session begins, and sharing finely-tuned and debugged JavaScript functions and data that can be invoked across different handlers and development projects.
For a detailed explanation of how to use this powerful feature, consult the [session initialization primer](https://frida.re/docs/frida-trace/session-initialization-primer/).
## -d, –decorate: add module name to log tracing
The `--decorate` option is relevant when `frida-trace` auto-generates JavaScript handler scripts. By default, a handler’s `onEnter` function looks like this:
`onEnter(log, args, state) {   log('memcpy()'); }, `
The drawback is that, if the same function name exists in multiple modules, it will be difficult to differentiate between function traces. The `--decorate` function instructs `frida-trace` to insert the module name in the default `onEnter` trace instruction:
`onEnter(log, args, state) {   log('memcpy() [msvcrt.dll]'); }, `
[Back](https://frida.re/docs/frida-ps/)
[Next](https://frida.re/docs/frida-discover/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
