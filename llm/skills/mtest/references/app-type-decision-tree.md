# App-Type Decision Tree

Determine app type after Phase 2 static analysis. Testing priorities shift based on what kind of app you're facing.

---

## App-Type Decision Tree

Your testing priorities shift based on what kind of app you're facing. Determine this after Phase 2 static analysis:

```
┌─────────────────────────────────────────────────────────────────────┐
│ BANKING / FINTECH (DexGuard, Eversafe, cert pinning, attestation)  │
│ Priority: Bypass → Traffic → IDOR on financial endpoints → Logic   │
│ Phase 3: heavy (30%+ if DexGuard/inline SVC present)               │
│ Phase 7: focus on payment, transfer, balance features              │
│ Phase 8: attestation replay within JWT TTL window                  │
│ Key findings: IDOR on accounts, race condition on transfers,       │
│   client-side PIN bypass, token leakage                            │
├─────────────────────────────────────────────────────────────────────┤
│ SOCIAL / MESSAGING (large attack surface, minimal protection)      │
│ Priority: Deep links → WebView → IDOR on user data → Injection    │
│ Phase 3: light (usually just SSL pinning, no RASP)                 │
│ Phase 7: focus on profile, messaging, file sharing, deep links     │
│ Phase 8: heavy (APIs often poorly protected)                       │
│ Key findings: IDOR on messages/profiles, XSS via WebView,         │
│   deep link hijacking, media file access                           │
├─────────────────────────────────────────────────────────────────────┤
│ UTILITY / OFFLINE (no network, local-only features)                │
│ Priority: Local storage → IPC → Content providers → Deep links     │
│ Phase 3: root detection only (no SSL pinning needed)               │
│ Phase 4/8: N/A (no network)                                        │
│ Phase 7: focus on data storage, exported components, file ops      │
│ Key findings: plaintext secrets, path traversal, content provider  │
│   injection, backup manipulation                                   │
├─────────────────────────────────────────────────────────────────────┤
│ GAME / UNITY IL2CPP (native logic, anti-cheat)                     │
│ Priority: global-metadata.dat → native RE → memory manipulation    │
│ Phase 2: jadx useless for game logic — focus on metadata strings   │
│ Phase 3: anti-cheat bypass (different from RASP)                   │
│ Phase 7: focus on in-app purchases, leaderboard, multiplayer       │
│ Key findings: purchase bypass, score manipulation, asset theft     │
├─────────────────────────────────────────────────────────────────────┤
│ FLUTTER (Dart AOT, BoringSSL, custom HTTP stack)                   │
│ Priority: libapp.so strings → Flutter SSL bypass → API testing     │
│ Phase 2: strings extraction from libapp.so (not jadx)              │
│ Phase 3: flutter_ssl_bypass.js + iptables DNAT (mandatory)         │
│ Phase 7: same as app category (banking Flutter, social Flutter)    │
│ Key findings: same as underlying category, plus Flutter-specific   │
│   issues (hardcoded keys in Dart snapshot, Hive unencrypted)       │
└─────────────────────────────────────────────────────────────────────┘
```

---