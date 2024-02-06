venv:
	python -m venv venv
	./venv/bin/pip install -e '.[development]'

checks: test stylecheck

test:
	pytest -v tests

stylecheck:
	pycodestyle -v --max-line-length=100 examples scapy_iscsi tests

clean:
	rm -rf venv
