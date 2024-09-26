all: req tests

req:
	pip install -r requirements.txt

tests:
	python3 ./tests/basic.py