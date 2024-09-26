all: req run

req:
	@ printf "⚙️ Installing requirements...\n"
	pip install -r requirements.txt
	@ printf "✅ Requirements installed successfully.\n"

run:
	@ printf "🚀 Running tests...\n"
	python3 ./tests/basic.py
	python3 ./tests/advanced.py
	python3 ./tests/security_analyzer.py
	@ printf "✅ All tests passed successfully.\n"
