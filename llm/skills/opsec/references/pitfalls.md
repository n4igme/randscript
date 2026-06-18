# OPSEC Pitfalls

1. **Git history is forever** — even after rewriting, cached commits and forks preserve old data
2. **Wayback Machine** — archived versions of profiles/sites may preserve removed info; request explicit removal
3. **Google cache** — removed pages may still appear in search results for weeks
4. **Social graph** — even if YOUR profile is clean, others may tag/mention you
5. **Metadata** — photos contain EXIF (GPS, device), PDFs contain author names
6. **Timing correlation** — commit timestamps reveal timezone, work hours
7. **Writing style** — stylometry can link anonymous accounts to known authors
8. **Don't overreact** — some exposure is acceptable/unavoidable; focus on what enables real attacks
9. **Prior knowledge contamination** — when assessing yourself, separate what you know internally from what's publicly discoverable. Test by asking: "Could a stranger find this?"
10. **Domain lapse risk** — expired domains can be weaponized for impersonation and email interception
11. **Certificate transparency is permanent** — crt.sh logs are append-only; subdomains you created are visible forever
12. **Employer derivability** — internal domain prefixes in commits (e.g., `dksec.local`) may be guessable if the company abbreviation is common
