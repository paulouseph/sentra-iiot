#!/usr/bin/env bash
# One-command start: checks deps, trains if needed, launches the server.
set -euo pipefail
cd "$(dirname "$0")"

PY=${PYTHON:-python3}

if [ ! -d .venv ]; then
  echo "==> Creating virtual environment"
  $PY -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> Installing dependencies"
pip install -q -r requirements.txt

if [ ! -f sentra/ml/artifacts/classifier.joblib ]; then
  if ls data/*EdgeIIoT*.csv >/dev/null 2>&1; then
    echo "==> Training on Edge-IIoTset"
    python -m sentra.ml.train
  else
    echo "==> No Edge-IIoTset CSV in data/ -- training on synthetic data."
    echo "    See data/README.md to get the real corpus."
    python -m sentra.ml.train --synthetic
  fi
fi

echo "==> Dashboard: http://127.0.0.1:8000/"
exec python -m uvicorn sentra.main:app --reload --port "${PORT:-8000}"
