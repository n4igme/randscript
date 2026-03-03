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
  * [](https://frida.re/docs/examples/ios/)
  * [GSoC Ideas 2015](https://frida.re/docs/gsoc-ideas-2015/)
  * [GSoD Ideas 2023](https://frida.re/docs/gsod-ideas-2023/)
  * [History](https://frida.re/docs/history/)


[ ](https://github.com/frida/frida-website/edit/main/_i18n/en/_docs/examples/ios.md)
# iOS
Frida provides wrapping functions for Objective-C selectors by replacing the `:` with `_`:
```
// +[NSJSONSerialization dataWithJSONObject:options:error:]
ObjC.classes.NSJSONSerialization.dataWithJSONObject_options_error_(...)

// NSString *helloWorldString = @"Hello, World!";
var helloWorldString = ObjC.classes.NSString.stringWithString_("Hello, World!");

// [helloWorldString characterAtIndex:0]
helloWorldString.characterAtIndex_(0)
```

> **Tip** : If things don’t seem to be working as expected you may be interacting with the wrong data type - run the following command to determine the actual type of the object that you’re dealing with!
```
console.log('Type of args[2] -> ' + new ObjC.Object(args[2]).$className)
```

## Converting NSData to String
```
const data = new ObjC.Object(args[2]);
data.bytes().readUtf8String(data.length());
```

> **Tip** : 2nd argument (number of bytes) is not required if the string data is null-terminated.
## Converting NSData to Binary Data
```
const data = new ObjC.Object(args[2]);
data.bytes().readByteArray(data.length());
```

## Iterating an NSArray
```
const array = new ObjC.Object(args[2]);
/*
 * Be sure to use valueOf() as NSUInteger is a Number in
 * 32-bit processes, and UInt64 in 64-bit processes. This
 * coerces it into a Number in the latter case.
 */
const count = array.count().valueOf();
for (let i = 0; i !== count; i++) {
  const element = array.objectAtIndex_(i);
}
```

## Iterating an NSDictionary
```
const dict = new ObjC.Object(args[2]);
const enumerator = dict.keyEnumerator();
let key;
while ((key = enumerator.nextObject()) !== null) {
  const value = dict.objectForKey_(key);
}
```

## Unarchiving an NSKeyedArchiver
```
const parsedValue = ObjC.classes.NSKeyedUnarchiver.unarchiveObjectWithData_(value);
```

## Reading a struct
If args[0] is a pointer to a struct, and let’s say you want to read the uint32 at offset 4, you can do it as shown below:
```
args[0].add(4).readU32();
```

## Displaying an alert box on iOS 7
```
const UIAlertView = ObjC.classes.UIAlertView; /* iOS 7 */
const view = UIAlertView.alloc().initWithTitle_message_delegate_cancelButtonTitle_otherButtonTitles_(
    'Frida',
    'Hello from Frida',
    NULL,
    'OK',
    NULL);
view.show();
view.release();
```

## Displaying an alert box on iOS >= 8
This is an implementation of the following [code](https://developer.apple.com/library/ios/documentation/UIKit/Reference/UIAlertController_class/).
```
// Defining a Block that will be passed as handler parameter to +[UIAlertAction actionWithTitle:style:handler:]
const handler = new ObjC.Block({
  retType: 'void',
  argTypes: ['object'],
  implementation() {
  }
});

// Import ObjC classes
const UIAlertController = ObjC.classes.UIAlertController;
const UIAlertAction = ObjC.classes.UIAlertAction;
const UIApplication = ObjC.classes.UIApplication;

// Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
ObjC.schedule(ObjC.mainQueue, () => {
  // Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
  const alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_('Frida', 'Hello from Frida', 1);
  // Again using integer numeral for style parameter that is enum
  const defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
  alert.addAction_(defaultAction);
  // Instead of using `ObjC.choose()` and looking for UIViewController instances
  // on the heap, we have direct access through UIApplication:
  UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
});
```

## Printing an NSURL argument
The following code shows how you can intercept a call to [UIApplication openURL:] and display the NSURL that is passed.
```
// Get a reference to the openURL selector
const openURL = ObjC.classes.UIApplication['- openURL:'];

// Intercept the method
Interceptor.attach(openURL.implementation, {
  onEnter(args) {
    // As this is an Objective-C method, the arguments are as follows:
    // 0. 'self'
    // 1. The selector (openURL:)
    // 2. The first argument to the openURL method
    const myNSURL = new ObjC.Object(args[2]);
    // Convert it to a JS string
    const myJSURL = myNSURL.absoluteString().toString();
    // Log it
    console.log('Launching URL: ' + myJSURL);
  }
});
```

[Back](https://frida.re/docs/examples/linux/)
[Next](https://frida.re/docs/examples/android/)
##### Sponsored by:
[ ![NowSecure](https://frida.re/img/nowsecure-logo.png) ](https://www.nowsecure.com)
