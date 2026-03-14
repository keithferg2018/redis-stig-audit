PYTHON ?= python3

run:
	$(PYTHON) audit.py --mode docker --container redis

json:
	$(PYTHON) audit.py --mode docker --container redis --json output/results.json
