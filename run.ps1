# Run the app using the project's venv python (no activation required)
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    & $venvPython app.py
} else {
    Write-Error ".venv not found. Activate a virtual env or run with 'python app.py'"
}