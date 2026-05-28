# CVSS Scoring Guidance for Financial Services

For targets in financial services (banking, multi-finance, insurance), consider upgrading severity when:

| Factor | Adjustment |
|--------|-----------|
| Exposed data enables fraud (credit scoring rules, approval thresholds) | +0.5–1.0 to base score |
| Regulatory violation (OJK, PBI, PCI-DSS, SOX) | Upgrade to next severity tier |
| Scope change (compromised service can access other services) | Use S:C (Changed) in CVSS vector |
| Data volume > 1000 records of business logic | Consider Critical even without PII |

**Key principle:** Business logic data (credit rules, approval hierarchies, risk matrices) can be MORE damaging than PII for financial institutions — it enables systematic fraud rather than individual identity theft.

## Regulatory Context (add to report when applicable)

| Country | Regulator | Relevant Rules |
|---------|-----------|---------------|
| Indonesia | OJK (Otoritas Jasa Keuangan) | POJK 11/2022 on IT risk management |
| Indonesia | Bank Indonesia | PBI on payment system security |
| Global | PCI-DSS | If payment card data in scope |
| US | SOX, GLBA | If US-listed or US operations |
| EU | GDPR, DORA | If EU customers or operations |
