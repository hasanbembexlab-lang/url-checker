# Website Diagnostic Monitor

A web interface for the supplied Python website diagnostics. It checks DNS,
SSL, HTTP, browser rendering, reputation, and common site-health issues.

## Requirements

- Python 3.10 or newer
- Internet access
- Chromium (installed by Playwright during setup)

## Run on Windows

From this folder in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m playwright install chromium
python -m uvicorn monitor:app
```

Then open <http://127.0.0.1:8000>.

Alternatively, run `npm run dev`. The script uses the project virtual
environment when available, installs missing Python requirements and
Playwright Chromium, then starts the Python FastAPI server. On Windows,
automatic reload is disabled because Uvicorn's reload worker uses an event
loop that does not support Playwright's browser subprocesses. If the app is
already running, npm reuses it; if port 8000 is occupied by another process,
it selects the next available port. Pass `--port 8766` to request a specific
port. The frontend is served by FastAPI and does not need a separate Node.js
build.

Run `npm run build` to check the frontend JavaScript syntax and compile-check
the Python backend. The app serves the frontend directly, so this validation
does not produce a separate frontend bundle.

The first setup downloads Chromium. If PowerShell blocks virtual-environment
activation, use `.\.venv\Scripts\python.exe` instead of `python` for each
command. On Linux, install Playwright's system packages with
`python -m playwright install --with-deps chromium`.

## Use

Enter one or more website addresses, separated by commas or new lines. Missing
`https://` is added automatically. Each batch can contain up to 100 websites.
Checks run in the background, and results are shown as each website completes.
Screenshots are written to the local `screenshots` folder.

The API is served from the same origin as the UI:

- `GET /api/health`
- `POST /api/checks` with `{"urls":"example.com,https://example.org"}`
- `GET /api/checks/{job_id}`
- `GET /api/screenshots/{filename}`
