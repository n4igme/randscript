# Security Skills — Validation & Maintenance

.PHONY: check lint refs test clean

check lint:
	@python3 scripts/validate_all.py

refs:
	@python3 scripts/check_cross_refs.py

test:
	@python3 -m pytest scripts/test_base.py -v

clean:
	@find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name .pytest_cache -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned __pycache__ and .pytest_cache directories"
