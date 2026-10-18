.PHONY: install test data sim ollama adaptive serve smoke latency

install:
	pip install -r requirements.txt

test:
	python -m pytest -q

data:            ## regenerate the synthetic corpus + attack suite files under data/
	python -m scripts.export_data

smoke:           ## fast end-to-end check (also run in CI)
	python -m eval.run_ablation --llm sim:llama-like --seeds 1 --configs main --limit 5 --out /tmp/rag-smoke

sim:             ## full ablation with the offline simulated LLM (3 profiles)
	python -m eval.run_ablation --llm sim:llama-like --seeds 3 --configs all --out results/sim-llama-like
	python -m eval.adaptive_run --llm sim:llama-like --seeds 3 --out results/sim-llama-like
	python -m eval.run_ablation --llm sim:qwen-like --seeds 3 --configs main --out results/sim-qwen-like
	python -m eval.run_ablation --llm sim:strong --seeds 3 --configs main --out results/sim-strong

ollama:          ## REAL local models (needs `ollama serve`, `ollama pull llama3.1:8b qwen2.5:7b`)
	python -m eval.run_ablation --llm ollama:llama3.1:8b --seeds 1 --configs main --judge llm --out results/ollama-llama3.1-8b
	python -m eval.adaptive_run --llm ollama:llama3.1:8b --seeds 1 --out results/ollama-llama3.1-8b
	python -m eval.run_ablation --llm ollama:qwen2.5:7b --seeds 1 --configs main --judge llm --out results/ollama-qwen2.5-7b
	python -m eval.adaptive_run --llm ollama:qwen2.5:7b --seeds 1 --out results/ollama-qwen2.5-7b

serve:
	uvicorn target.service:app --port 8000

latency:         ## isolated latency of the non-LLM stages (run on an idle machine)
	python -m eval.latency_bench --out results/latency_bench.csv
