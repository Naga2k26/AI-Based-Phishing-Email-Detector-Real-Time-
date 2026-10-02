@echo off
REM Start the app using the venv python if present, otherwise fallback to system python
if exist ".venv\Scripts\python.exe" (
  .venv\Scripts\python.exe app.py
) else (
  python app.py
)
pause