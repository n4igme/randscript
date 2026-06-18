# Phase 4: Cross-Reference Chain Analysis

Map how identities connect and identify **single points of failure**:

```
[Handle A] ──direct link──→ [Handle B] ──git commit──→ [Real Name + Email]
                                                              │
                                                    [Wedding Site] ──→ [Address, Family, Bank]
```

**Metrics:**
- **Chain length:** How many hops from anonymous handle to real identity?
- **Single points of failure:** Which ONE link, if removed, breaks the chain?
- **Redundant paths:** Can the chain be rebuilt via alternate routes?

**Ideal state:** Minimum 3+ hops between public security persona and real identity, with no single point of failure.
