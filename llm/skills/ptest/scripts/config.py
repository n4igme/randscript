SKILL_CONFIG = {
    'NAME': 'ptest',
    'OUTPUT_DIR': 'ptest-output',
    'PHASES': {
        1: 'passive_recon',
        2: 'active_recon',
        3: 'enumerate_confirm',
        4: 'assess_exploit',
        5: 'post_exploit_impact',
        6: 'reporting',
    },
    'GATEWAYS': {
        1: '1_passive_recon',
        2: '2_active_recon',
        3: '3_enumerate_confirm',
        4: '4_assess_exploit',
        5: '5_post_exploit_impact',
        6: '6_reporting',
    },
    'SUBDIRS': [
        'phase1-recon',
        'phase2-active',
        'phase3-enumerate-confirm',
        'phase4-assess-exploit',
        'phase5-post-exploit',
        'report',
    ],
    'BUDGET_HOURS': 16,
}
