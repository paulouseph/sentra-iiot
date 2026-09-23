# One-command start for Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .venv)) {
    Write-Host "==> Creating virtual environment"
    python -m venv .venv
}
& .\.venv\Scripts\Activate.ps1

Write-Host "==> Installing dependencies"
pip install -q -r requirements.txt

if (-not (Test-Path sentra\ml\artifacts\classifier.joblib)) {
    if (Get-ChildItem data -Filter *EdgeIIoT*.csv -ErrorAction SilentlyContinue) {
        Write-Host "==> Training on Edge-IIoTset"
        python -m sentra.ml.train
    } else {
        Write-Host "==> No Edge-IIoTset CSV in data\ -- training on synthetic data."
        Write-Host "    See data\README.md to get the real corpus."
        python -m sentra.ml.train --synthetic
    }
}

Write-Host "==> Dashboard: http://127.0.0.1:8000/"
python -m uvicorn sentra.main:app --reload --port 8000
