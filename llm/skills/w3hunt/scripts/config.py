SKILL_CONFIG = {
    'NAME': 'w3hunt',
    'BUDGET_HOURS': 8,
    'OUTPUT_DIR': 'w3hunt-output',
    'GATEWAYS': {
        1: '1_triage',
        2: '2_recon',
        3: '3_web_assessment',
        4: '4_sc_audit',
        5: '5_exploit_submit',
    },
    'PHASES': {
        1: 'triage',
        2: 'recon',
        3: 'web-assessment',
        4: 'sc-audit',
        5: 'exploit-submit',
    },
    'SUBDIRS': [
        'phase1-triage',
        'phase2-recon',
        'phase3-web',
        'phase4-sc-audit',
        'phase5-exploit-submit',
    ],
}
