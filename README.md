# SENTRA-IIoT 

Threat detection for industrial IoT networks, trained on the Edge-IIoTset corpus. A FastAPI service classifies network flows into fifteen attack classes, explains each verdict in plain English, and serves an analyst console that updates live over a WebSocket.

This is a rebuild of the v1 prototype. Section [What changed](#what-changed-from-v1) lists what moved and why.

## Quick start

```bash
# 1. dependencies
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. configuration
cp .env.example .env
#    edit .env — set your own API key and any dataset/path overrides you need

# 3. dataset  (see data/README.md)
#    download ML-EdgeIIoT-dataset.csv from Kaggle into data/

# 4. train
python -m sentra.ml.train

# 5. run
uvicorn sentra.main:app --reload
```

On Windows, `run.ps1` wraps the same steps into a single script — run `.\run.ps1` after the dataset is in place instead of the `uvicorn` command above.

Then open http://127.0.0.1:8000/. API docs are at `/docs`.

No dataset to hand? `python -m sentra.ml.train --synthetic` trains on a generated stand-in so you can see the system work. The dashboard will show a banner telling you the numbers are not meaningful, because they are not.

## Layout

```
sentra-iiot/
├── sentra/
│   ├── main.py            app factory, lifespan, serves the dashboard
│   ├── config.py          every tunable, overridable from .env
│   ├── taxonomy.py        15 classes -> family, severity, story, actions
│   ├── engine.py          inference, novelty scoring, explanation
│   ├── narrator.py        verdict -> English
│   ├── assets.py          the plant inventory alerts are bound to
│   ├── store.py           SQLite persistence + audit trail
│   ├── streamer.py        replay pool, WebSocket fan-out, live loop
│   ├── security.py        API key + rate limiting
│   ├── runtime.py         startup wiring, injected into routers
│   ├── api/               system.py · detect.py · alerts.py
│   └── ml/
│       ├── schema.py      leakage drop list, friendly feature names
│       ├── edge_iiotset.py   the real loader
│       ├── synthetic.py   fallback generator
│       ├── train.py       training + evaluation pipeline
│       └── artifacts/     generated: model, metrics, replay pool
├── frontend/              index.html · styles.css · app.js  (no build step)
├── tests/                 22 tests over the API, engine and taxonomy
├── data/                  put the Edge-IIoTset CSV here
└── docs/report-update.md  rewritten report sections
```

## The detection pipeline

**Classifier.** A Random Forest over all fifteen Edge-IIoTset classes. The six-way operational family (Denial of service, Interception, Reconnaissance, Malware, Application abuse, Normal) is derived afterwards from `taxonomy.py`. Training on the coarse labels instead would throw away the difference between a port scan and a vulnerability scan, which matters to the analyst even though both are reconnaissance.

**Leakage removal.** Edge-IIoTset ships raw capture artefacts — timestamps, host addresses, full URIs, payloads. A tree will happily learn `ip.src_host == 192.168.0.152 → Backdoor` and report accuracy that means nothing. `ml/schema.py` drops 22 such columns before training.

**Novelty.** An Isolation Forest fitted on the whole training distribution. The Random Forest can only ever answer "which of these fifteen", so on genuinely new traffic it is confidently wrong. The novelty score lets the engine say *this resembles nothing I was trained on*, which is the zero-day gap the v1 report identified. It flags roughly 0.5% of held-out flows.

**Explanation.** For each alert, every feature's distance from quiet-hours normal (a z-score against `baseline.json`) is weighted by how much the forest cares about that feature overall. The top-ranked few become sentences. It is a cheap local approximation of a SHAP attribution that runs in microseconds rather than seconds — which matters when the whole classification budget is a few milliseconds.

## The console

Five views, reachable with keys 1–5:

| View | What it is for |
|---|---|
| The floor | Ten named plant assets. Tiles flash as traffic is classified against them and carry the consequence of losing that asset. |
| Live feed | Every classified flow, filterable by severity, search and "only what needs a human". Click for the full verdict. |
| Triage | Open work as a board: New → Investigating → Contained → Closed. Every move is written to the audit trail. |
| Drill range | Fire a controlled burst of any of the fifteen classes and watch the model answer. |
| The model | Accuracy, balanced accuracy, cross-validated F1, confusion matrix, feature importance, baselines, latency. |

Alerts are written for a human, not a log parser:

> **Ransomware behaviour on an engineering host — near certain (0.976)**
>
> Traffic shows bulk encrypted transfer alongside rapid file-share access. On an OT network this usually means an engineering workstation is encrypting what it can reach — including project files.
>
> HTTP body size is 938.8 bytes — nothing like normal, 47.0× the usual 20.0 bytes.
>
> **Do this next:** Disconnect the host physically; do not rely on a software block.

Confidence is a word before it is a number. 0.61 reads as certainty to most people and it is not; the console says "likely", and below 0.4 it says "guessing" and refuses to present the result as a finding.

## API

Reads are open. Anything that changes state needs `X-API-Key` (set your own in `.env` — see Quick start).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Liveness, model state, stream state |
| GET | `/api/model/card` | Full evaluation report |
| GET | `/api/assets` | Plant inventory with live event counts |
| GET | `/api/taxonomy` | Classes, families, severities, analyst profiles |
| POST | `/api/predict` | Classify one flow |
| POST | `/api/simulate` 🔑 | Inject a drill burst |
| GET | `/api/alerts` | Feed, with filters and pagination |
| PATCH | `/api/alerts/{id}/status` 🔑 | Move through triage |
| PATCH | `/api/alerts/{id}/assignee` 🔑 | Assign |
| POST | `/api/alerts/{id}/notes` 🔑 | Analyst note |
| DELETE | `/api/alerts` 🔑 | Clear the alert table (audited) |
| GET | `/api/stats`, `/api/timeline` | Dashboard aggregates |
| GET | `/api/audit` | Who did what |
| POST | `/api/stream` 🔑 | Pause, resume or re-tune the live feed |
| WS | `/ws/live` | Push channel for new alerts |

```bash
curl -X POST localhost:8000/api/simulate \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: <your key from .env>' \
  -d '{"attack_type": "Ransomware", "count": 5}'
```

## Tests

```bash
pytest -q          # 22 tests
```

They run against a throwaway SQLite file and the real trained artifacts, so a green run means the shipped system works rather than a mock of it. Coverage includes the auth boundary (simulation without a key must 401), the triage workflow end to end, filter and pagination behaviour, that the headline accuracy beats the majority-class baseline, and that every class in the taxonomy has analyst-facing guidance attached.

## What changed from v1

| | v1 | v2 |
|---|---|---|
| Data | 18k synthetic rows, 6 classes separable by construction | Edge-IIoTset, 15 classes, leakage columns removed |
| Reported accuracy | 99.97% | Whatever the real corpus gives — the pipeline no longer flatters itself |
| Evaluation | One split, accuracy and F1 | Balanced accuracy, 5-fold CV, baselines to beat, p50/p95/p99 latency |
| Storage | Python list capped at 500; a restart erased everything | SQLite with WAL, notes, and an audit trail |
| WebSocket | Endpoint existed; the frontend polled every 4s anyway | Socket is primary, polling is the fallback |
| Auth | `allow_origins=["*"]`, every route open | API key on mutating routes, rate limit on simulation |
| Zero-day | Listed as a limitation | Isolation Forest novelty score on every alert |
| Explanation | Label plus a confidence decimal | Narrative, ranked evidence, recommended actions, second opinion |
| Alert target | A bare IP | A named asset with its zone and operational consequence |
| Tests | None; verification was manual | 22 automated tests |
| Demo honesty | Replayed the training generator | Replays held-out rows and shows live accuracy against ground truth |

## Dataset citation

Ferrag, M. A., Friha, O., Hamouda, D., Maglaras, L., & Janicke, H. (2022). Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT Applications for Centralized and Federated Learning. *IEEE Access*, 10, 40281–40306.

## License
MIT License

Copyright (c) 2026 Paul Ouseph, Jerine C Binu

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
