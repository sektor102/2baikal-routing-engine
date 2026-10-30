PYTHON ?= python
MIHOMO ?= .cache/tools/mihomo
XRAY ?= .cache/tools/xray
REPOSITORY ?= sektor102/2baikal-routing-engine

.PHONY: tools fetch build test audit validate smoke
tools:
	$(PYTHON) scripts/install_tools.py
fetch:
	$(PYTHON) -m engine fetch
build:
	$(PYTHON) -m engine build --mihomo "$(MIHOMO)" --repository "$(REPOSITORY)" --previous .previous-release
test:
	$(PYTHON) -m unittest discover -s tests -v
audit:
	$(PYTHON) -m engine audit
validate:
	$(PYTHON) -m engine validate --mihomo "$(MIHOMO)" --xray "$(XRAY)" --require-binaries
smoke:
	$(PYTHON) -m unittest discover -s tests -v
