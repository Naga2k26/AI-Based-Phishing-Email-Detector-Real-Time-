#!/usr/bin/env bash
# Run the app using venv python if present
if [ -x ".venv/bin/python" ]; then
  ./.venv/bin/python app.py
else
  echo ".venv not found. Activate a virtual environment or run: python app.py"
fi