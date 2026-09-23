# Put the dataset here

SENTRA-IIoT trains on **Edge-IIoTset** (Ferrag, Friha, Hamouda, Maglaras &
Janicke, *IEEE Access*, 2022).

Download: https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot

You need one of these two files in this folder:

| File | Rows | Notes |
|---|---|---|
| `ML-EdgeIIoT-dataset.csv` | ~157,800 | Pre-sampled. Trains in about a minute. **Start here.** |
| `DNN-EdgeIIoT-dataset.csv` | ~2.2M | Full corpus. Use `--max-rows` unless you have ~8 GB free. |

Then:

    python -m sentra.ml.train

If neither file is present the trainer falls back to a synthetic generator and
says so, loudly, in the console and on the dashboard's model page. That mode
exercises the pipeline but its accuracy figures mean nothing — do not put them
in the report.

Nothing in this folder is committed; see `.gitignore`.
