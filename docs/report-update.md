# SENTRA-IIoT — report update pack (v1 → v2)

Drop-in replacements for the sections of the project report that the rebuild
invalidates. Everything marked `[FILL]` needs a number from your own training
run — run `python -m sentra.ml.train` on the real Edge-IIoTset CSV, then read
`sentra/ml/artifacts/metrics.json`, or just read the figures off the model page
in the dashboard.

Sections not listed here (problem statement, literature survey, SRS functional
requirements, references) stand unchanged.

---

## 0. Abstract — replacement

> Industrial IoT deployments expose control equipment that was designed for
> isolated networks to routed, internet-adjacent traffic. This project presents
> SENTRA-IIoT, a detection and triage platform that classifies industrial
> network flows into fifteen attack categories and presents each verdict in a
> form a shift analyst can act on.
>
> The detector is a Random Forest trained on Edge-IIoTset (Ferrag et al., 2022),
> a corpus of real IoT and IIoT capture covering DDoS, reconnaissance,
> adversary-in-the-middle, malware, injection and credential attacks across
> MQTT, Modbus/TCP, HTTP, DNS and ICMP. Twenty-two identity and payload columns
> are removed before training to prevent the model memorising source addresses
> instead of learning behaviour. An Isolation Forest fitted on the same training
> distribution supplies a novelty score, allowing the system to report that a
> flow resembles nothing it was trained on rather than forcing it into the
> nearest known class.
>
> The system achieves `[FILL accuracy]` accuracy and `[FILL macro F1]` macro F1
> on a held-out 20% split, with `[FILL balanced accuracy]` balanced accuracy and
> a cross-validated macro F1 of `[FILL cv mean ± std]` over five folds. Mean
> single-flow classification latency is `[FILL mean_ms]` ms, against a
> requirement of 2,000 ms.
>
> Verdicts are delivered through a browser console that binds every alert to a
> named plant asset, states the operational consequence of losing that asset,
> ranks the measurements that drove the classification, and gives the analyst a
> checklist of next actions. Alerts persist to an embedded database with a full
> audit trail, and state-changing operations are authenticated. A suite of 22
> automated tests covers the API surface, the authorisation boundary and the
> triage workflow.

---

## 1. Chapter 3 — System design, replacement sections

### 3.2 Architecture

SENTRA-IIoT is a single FastAPI process serving three concerns: a detection
engine, a persistence and triage layer, and a static analyst console. There is
no separate frontend server, which keeps the deployment to one command and one
origin.

```
                        ┌──────────────────────────────┐
  Edge-IIoTset CSV ───► │  ml/train.py                 │
                        │  clean · split · fit · score │
                        └──────────────┬───────────────┘
                                       │ artifacts/
                    ┌──────────────────▼──────────────────┐
                    │  classifier · novelty · scaler      │
                    │  metadata · metrics · baseline      │
                    │  replay pool (held-out real rows)   │
                    └──────────────────┬──────────────────┘
                                       │
  ┌────────────┐   flow    ┌───────────▼───────────┐   alert   ┌──────────────┐
  │ /api/      │──────────►│  DetectionEngine      │──────────►│  AlertStore  │
  │ predict    │           │  align → predict →    │           │  SQLite WAL  │
  │ simulate   │           │  novelty → deviation  │           │  notes+audit │
  │ LiveStream │           │  → narrator           │           └──────┬───────┘
  └────────────┘           └───────────────────────┘                  │
                                       │ broadcast                    │ query
                           ┌───────────▼───────────┐          ┌───────▼───────┐
                           │  ConnectionManager    │          │  REST routers │
                           │  WebSocket /ws/live   │          │  /api/alerts  │
                           └───────────┬───────────┘          └───────┬───────┘
                                       └──────────┬───────────────────┘
                                          ┌───────▼────────┐
                                          │  Analyst console│
                                          └─────────────────┘
```

Module responsibilities:

| Module | Responsibility |
|---|---|
| `ml/schema.py` | Feature-space definition: leakage drop list, analyst-readable feature names |
| `ml/edge_iiotset.py` | Loading, de-duplication, categorical encoding, stratified subsampling |
| `ml/train.py` | Training, evaluation, artifact generation, replay-pool construction |
| `taxonomy.py` | The 15 classes mapped to family, severity, narrative and recommended actions |
| `engine.py` | Inference, novelty scoring, per-alert deviation analysis |
| `narrator.py` | Verdict rendered as English, including confidence bands |
| `assets.py` | Plant inventory; binds every alert to named equipment |
| `store.py` | SQLite persistence, triage state, notes, audit trail |
| `streamer.py` | Replay pool, live production loop, WebSocket fan-out |
| `security.py` | API key enforcement, simulation rate limiting |
| `runtime.py` | Startup wiring; dependency-injected so tests can substitute a temporary database |

### 3.3 Threat taxonomy

Edge-IIoTset labels traffic with fifteen fine-grained attack types. The
classifier predicts all fifteen; a six-way operational family is derived
afterwards. Training on the coarse labels directly would discard the
distinction between a port scan and a vulnerability scan — both reconnaissance,
but different responses.

| Family | Edge-IIoTset classes | Severity |
|---|---|---|
| Normal | Normal | info |
| Denial of service | DDoS_UDP, DDoS_ICMP, DDoS_TCP, DDoS_HTTP | critical / high |
| Interception | MITM | high |
| Reconnaissance | Port_Scanning, Vulnerability_scanner, Fingerprinting | low / medium |
| Malware | Backdoor, Ransomware | critical |
| Application abuse | SQL_injection, XSS, Uploading, Password | medium / high |

Each class carries an analyst profile: a headline, a plain-English explanation
of what the pattern means on an OT network, a list of recommended actions, and
a MITRE ATT&CK for ICS technique reference. Keeping these in one table means
the model, the API, the console and this report cannot disagree about what a
classification means.

### 3.4 Data preparation and leakage control

Edge-IIoTset is distributed as raw capture with 63 columns. Fifteen of these
are identity or timing artefacts (`frame.time`, `ip.src_host`, `ip.dst_host`,
`arp.src.proto_ipv4`, port numbers, checksums, sequence numbers) and seven are
raw payload content (`tcp.payload`, `http.file_data`, `http.request.full_uri`,
`mqtt.msg`, `dns.qry.name` and related). Both groups leak.

Identity columns leak because the corpus was captured on a fixed testbed: each
attack was launched from a known host, so a tree can learn the source address
and achieve near-perfect accuracy without learning anything about traffic
behaviour. Payload columns leak because an injection attack's payload *is* the
label written out in text.

All 22 are dropped before training. Exact duplicate rows are also removed —
Edge-IIoTset contains many, and leaving them in place puts identical samples in
both the training and test splits, inflating the reported score.

`[FILL: after your training run, quote the two lines from metrics.json's
dataset_notes: rows read, duplicates dropped, final feature count.]`

### 3.5 Novelty detection

A supervised classifier can only answer "which of these fifteen". Presented
with traffic outside its training distribution it returns a nearest label with
high confidence, which is precisely the wrong behaviour on the first day of a
zero-day.

An Isolation Forest is therefore fitted on the whole training distribution, and
the threshold set at the 0.5th percentile of training scores. A flow scoring
below it is marked as resembling nothing in the corpus. The classifier still
reports its nearest label, but the console presents it as a best guess and
escalates the severity floor to *medium* — traffic the system has never seen is
never routine.

Fitting on the whole distribution rather than on Normal traffic alone is a
deliberate choice. Fitting on Normal alone makes every known attack score as
anomalous, and the flag stops carrying information. Measured on the held-out
set, the chosen configuration flags `[FILL flagged_share_of_holdout]` of flows.

### 3.6 Explanation of individual alerts

Global feature importance describes the model, not a particular packet. To
explain one alert the engine combines two quantities per feature: the distance
from quiet-hours normal, as a z-score against a stored baseline of
normal-traffic statistics, and the forest's global importance for that feature.
The product ranks which measurements to show the analyst.

This is a local approximation of a Shapley attribution. A full SHAP computation
over a 300-tree forest takes on the order of seconds per sample, which cannot
sit inside a per-flow classification budget of milliseconds; the approximation
runs in microseconds and, in a setting where the top three drivers are what the
analyst reads, is sufficient. Exact attribution on demand, computed only for
alerts the analyst opens, is identified as future work.

### 3.7 Interface design

The console is organised around what a shift analyst does rather than around
what the system stores:

- **The floor** — ten named assets as instrument tiles, each showing its zone,
  its current worst classification in plain English, and the operational
  consequence of losing it. Tiles flash as traffic is classified against them.
- **Live feed** — every classified flow, filterable by severity, free text,
  and "only what needs a human". Opening a row shows the full verdict.
- **Triage** — open work as a four-column board, ordered by severity weighted
  by asset criticality, so a critical on a safety controller outranks a
  critical on a badge reader.
- **Drill range** — controlled injection of any class, with the model's score
  against ground truth reported per drill.
- **The model** — the full evaluation report, including a confusion matrix
  heat map and the baselines the headline figure has to beat.

Two design commitments run through all five. First, confidence is expressed as
a word before it is expressed as a number: `0.61` reads as certainty to most
readers, so the interface says *likely*, and below 0.40 says *guessing* and
declines to present the result as a finding. Second, no alert is displayed
without a recommended action — a classification the analyst cannot act on is a
notification, not a detection.

---

## 2. Chapter 4 — Implementation, replacement sections

### 4.1 Training pipeline

`python -m sentra.ml.train` performs the full offline pipeline: load, clean,
stratified 80/20 split, fit, evaluate, and write artifacts. Flags exist for a
row cap (`--max-rows`, stratified so rare classes survive), a synthetic
fallback (`--synthetic`), and for skipping cross-validation or baselines on a
slow machine.

Hyperparameters: 300 trees, maximum depth 24, minimum two samples per leaf,
`class_weight="balanced_subsample"` to stop the majority Normal class
dominating, fixed random seed for reproducibility.

Six artifacts are written: the classifier, the novelty model, the scaler,
metadata (feature order, class order, categorical encodings), the full metrics
report, the normal-traffic baseline used for explanations, and a replay pool.

### 4.2 The replay pool

The replay pool is a sample of held-out test rows, saved with their true
labels. The live stream and the drill range both draw from it.

This matters for the demonstration's validity. The v1 dashboard was driven by
the same synthetic generator the model was trained on, so the demonstration
could never disagree with the model — an impressive loop that proved nothing.
Here, every flow shown on screen is a real sample the classifier has never
seen, and its true label travels with it. The console therefore reports a
running live accuracy, and a misclassification is visible as it happens rather
than hidden.

### 4.3 Persistence

Alerts are written to SQLite in WAL mode. Hot filter columns (timestamp,
severity, family, status, asset) are stored as indexed columns; the full alert
is stored alongside as a JSON document, so adding a field to an alert requires
no schema migration. Two further tables hold analyst notes and an append-only
audit log of privileged actions.

SQLite is the appropriate choice at this scale: it provides durability, real
queries and an audit trail that survives a crash, with no server to install.
The v1 design — a Python list truncated at 500 entries — lost the entire event
history on every restart, which the v1 report itself identified as the system's
principal weakness.

### 4.4 Live delivery

The backend broadcasts each new alert over `/ws/live`. The console connects on
load and falls back to three-second polling only if the socket cannot be
established, reconnecting in the background.

The v1 build exposed the same WebSocket endpoint but the frontend polled every
four seconds regardless, so a critical alert could sit unseen for four seconds
while a push channel stood idle. The v2 console consumes the socket it is
given.

### 4.5 Access control

Read endpoints are open, so the dashboard works without a login flow. Every
state-changing endpoint — simulation, triage updates, notes, clearing the alert
table, retuning the stream — requires a shared key in an `X-API-Key` header.
Simulation additionally carries a sliding-window rate limit of twenty calls per
minute per client, so the drill harness cannot be turned into the
denial-of-service tool it simulates. CORS is restricted to configured origins
rather than `*`.

This is deliberately not a full OAuth2 or RBAC implementation. For a
single-site prototype, a shared key that is actually enforced is worth more
than an elaborate scheme that is half-finished; role-based access control
belongs in future work.

---

## 3. Chapter 5 — Testing and evaluation, replacement

### 5.1 Automated test suite

The v1 report states that no automated tests existed and that verification was
performed manually. Twenty-two tests now run under `pytest`, against a
throwaway database and the real trained artifacts, so a passing run exercises
the shipped system rather than a mock.

| Group | What it establishes |
|---|---|
| Taxonomy consistency | Every class the model can emit has analyst guidance attached |
| Health and model card | Metrics are internally consistent; balanced accuracy ≤ accuracy; the headline beats the majority-class baseline |
| Classification | Alerts are structurally complete; partial feature sets are tolerated; malformed bodies are rejected with 422; latency is within the NFR |
| Authorisation | Simulation and clearing without a key return 401 |
| Input validation | Unknown attack classes rejected with 400; burst counts outside 1–50 rejected with 422 |
| Triage workflow | Status transitions, assignment and notes persist and are readable back |
| Feed | Severity filtering and pagination behave; unknown ids return 404 |
| Persistence and audit | Event counts survive across operations; privileged actions appear in the audit log |

### 5.2 Model evaluation

`[FILL from metrics.json — the table below shows the shape to use.]`

| Measure | Value | Reading |
|---|---|---|
| Accuracy | `[FILL]` | Share of held-out flows classified correctly |
| Balanced accuracy | `[FILL]` | The same with every class weighted equally — the honest figure on an imbalanced corpus |
| Macro F1 | `[FILL]` | Unweighted mean F1 across the fifteen classes |
| Weighted F1 | `[FILL]` | Weighted by class support |
| Cross-validated macro F1 | `[FILL] ± [FILL]` | Five stratified folds; confirms the headline is not one lucky split |
| Attack detection rate | `[FILL]` | Share of hostile flows that raised an alert |
| False alarm rate | `[FILL]` | Share of normal flows that raised an alert |

Reporting balanced accuracy alongside accuracy is not decoration. Edge-IIoTset
is imbalanced, and a model can post a strong accuracy figure while failing
entirely on the rarest and often most serious classes. Where the two diverge,
the gap is the honest description of the model's weakness.

### 5.3 Baseline comparison

A headline accuracy figure means nothing without something to beat. Two
baselines are trained on the same split:

| Model | Accuracy | Macro F1 |
|---|---|---|
| Majority class | `[FILL]` | `[FILL]` |
| Single decision tree (depth 12) | `[FILL]` | `[FILL]` |
| **Random Forest (this system)** | `[FILL]` | `[FILL]` |

### 5.4 Latency against the non-functional requirement

The SRS sets a 2,000 ms budget per event. Latency is measured over 200
single-sample inferences in the same code path the API uses.

| Statistic | Value |
|---|---|
| Mean | `[FILL mean_ms]` ms |
| Median | `[FILL p50_ms]` ms |
| 95th percentile | `[FILL p95_ms]` ms |
| 99th percentile | `[FILL p99_ms]` ms |

Reporting percentiles rather than a mean alone matters for a requirement
expressed as a ceiling: a mean can sit comfortably inside the budget while a
tail exceeds it.

### 5.5 Per-class performance

`[FILL — copy the per-class table from the dashboard's model page, which
already carries a plain-English reading for each row.]`

The classes to discuss are the weakest ones, and the confusion matrix shows
where their errors go. Errors within a family (one DDoS variant called as
another) cost the analyst little, since the response is the same. Errors across
families — reconnaissance called as normal, or malware called as application
abuse — are the ones that matter operationally, and those are the cells to
name explicitly.

---

## 4. Chapter 6 — Limitations and future work, replacement

### Resolved since v1

| v1 limitation | Resolution |
|---|---|
| Synthetic dataset; accuracy not transferable | Trained on Edge-IIoTset with leakage columns removed |
| Alerts held in memory; lost on restart | SQLite with WAL, notes and audit trail |
| WebSocket endpoint unused by the frontend | Console consumes the socket; polling is the fallback |
| All endpoints unauthenticated, CORS open to `*` | API key on mutating routes, rate-limited simulation, restricted origins |
| No zero-day capability | Isolation Forest novelty score on every alert |
| No automated tests | 22 tests covering API, auth boundary and workflow |
| Alerts reported a label and a decimal | Narrative, ranked evidence, recommended actions, named asset |

### Remaining

**No live packet capture.** Flows arrive through the API or the replay pool,
not from a network interface. Production deployment needs a capture agent
computing the Edge-IIoTset feature set from live traffic — realistically a
Zeek or CICFlowMeter pipeline feeding `/api/predict`.

**Dataset-bound coverage.** The model recognises what Edge-IIoTset contains.
Protocols and attack techniques absent from the corpus fall to the novelty
detector, which reports that something is unfamiliar but cannot say what.

**No concept-drift handling.** Plant traffic changes as equipment is
commissioned and processes are re-tuned. There is no retraining trigger and no
drift monitor; the normal-traffic baseline used for explanations is fixed at
training time.

**Approximated explanations.** The deviation ranking is a fast approximation of
a Shapley attribution, not the attribution itself. Computing exact SHAP values
on demand for opened alerts would be a contained improvement.

**Single shared credential.** One API key with one privilege level. Real SOC
operation needs per-analyst identity, role separation between reading and
containment actions, and attribution of audit entries to people rather than to
"operator".

**Single-node deployment.** One process, one SQLite file. Throughput is
adequate for a dashboard but not for plant-wide packet volume; that needs a
queue in front of the engine and a time-series store behind it.

---

## 5. Figures to capture

Screenshots to take once you have trained on the real corpus. Every one of
these is a live view — none needs mocking up.

1. **The floor**, with a critical alert active, so tiles show the severity ramp.
2. **A detail drawer**, opened on a Ransomware or Backdoor alert — this is the
   figure to use when discussing explainability, because it shows narrative,
   evidence, probability split and actions in one frame.
3. **The triage board**, with cards in at least three columns.
4. **The drill range**, immediately after a burst, showing the detection score
   in the drill log.
5. **The model page**, showing the confusion matrix and the baseline
   comparison.
6. **The console output of `pytest -q`**, for the testing chapter.
7. **The training console output**, showing dataset notes, accuracy, detection
   rate and false alarm rate.

The model page renders in a light theme too (the ◐ button), which reproduces
better in print than the dark console.
