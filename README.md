# IncidentOps

An incident-response console that compares a stateless Groq answer with a Hindsight-grounded answer. Memory starts empty, and only lessons an engineer explicitly approves are retained.

## Requirements

- Python 3.11+
- A Groq API key with access to `openai/gpt-oss-120b`
- A Hindsight Cloud project, API key, and base URL

## Setup

1. Create and activate a virtual environment.

   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

2. Install dependencies and configure credentials.

   ```powershell
   python -m pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

   Fill in `GROQ_API_KEY`, `HINDSIGHT_API_KEY`, and `HINDSIGHT_BASE_URL` in `.env`. Keep `.env` private; it is ignored by Git.

3. Start the app.

   ```powershell
   uvicorn main:app --reload
   ```

   Open <http://127.0.0.1:8000>. The app uses the Hindsight Cloud service at the configured base URL; it does not start or provision a Hindsight server.

4. Optional real-data demo seed:

   ```powershell
   python seed_real_data.py
   ```

   The script streams `threatcluster/threat-incident-clusters`, retains up to 15 multi-source security incident summaries in `incidentops-v1`, and downloads a 200-line real LogHub BGL sample to `data/loghub_bgl_sample.log`. It may take a few minutes because it scans the public dataset and calls Hindsight once per selected incident. It is safe to rerun: each security incident uses a stable Hindsight document ID.

## Demo flow

1. Use **Cold Start** to switch the running app to a fresh, empty bank. Existing banks are not deleted.
2. Ask an incident question. The left panel is stateless; the right panel shows the actual number of recalled memory units and any returned evidence.
3. Approve a durable lesson in the review dialog, or reject it. Only the explicit approval action calls Hindsight `retain`.
4. Ask a similar question again. The memory-grounded response can use the approved lesson; the stateless baseline has no memory.
5. Ask an unrelated question to exercise the scope guard. Try a new incident category to see the `No relevant memory found` abstention.
6. Use **Ingest Logs** to paste operational logs or click **Load LogHub sample** after running the seed script.

The demo seed uses real security incident summaries as memory, so a seeded bank is not a “Cold Start”. Use the reset button to demonstrate the empty state first.

## Tests

```powershell
pytest -q
```

The triage tests mock external providers and verify parallel-answer response shape, real recalled-count reporting, and that out-of-scope questions make no provider calls.

## Architecture

```text
Browser (plain HTML / CSS / JS)
  |  POST /api/triage
  v
FastAPI scope guard
  |-- out of scope --> fixed response; no provider calls
  `-- in scope ------> Hindsight recall (top 5, <=300 chars each)
                         |
                         +--> Groq, stateless -----------+
                         `--> Groq, recalled context ----+--> side-by-side UI

Engineer approval --> POST /api/lessons/approve --> Hindsight retain
Ingested log text --> same scope/recall + parallel triage path
Sandbox -----------> Hindsight recall / reflect
```

## How Hindsight memory is used

- **Banks:** the real-data seed uses the stable bank `incidentops-v1`. The app starts on that bank. **Cold Start** switches the current process to a new, uniquely named empty bank; it does not delete or mutate prior banks. Restarting the app returns to `incidentops-v1`.
- **retain:** the only application path that retains engineer-authored/generated lesson text is `/api/lessons/approve`. The UI opens an editable review dialog, and no retain request is sent until the engineer submits approval. Model output is never automatically retained. The seed script is the separate, explicit import path for attributed public incident records.
- **recall:** each in-scope triage recalls from the active bank before model calls. At most five results are passed onward, each truncated to 300 characters, with a bounded recall token budget. The grounded system instruction prohibits citing anything outside the returned “Recalled memories” section; with zero results the backend explicitly prefixes `No relevant memory found` and the UI hides the learned badge.
- **reflect:** the Sandbox calls Hindsight `reflect` for a direct, disposition-aware answer. Its raw response is shown separately from the Groq comparison.
- **Visibility:** the `Grounded on N recalled lessons` value is based on the actual result list returned for that specific triage, not the total bank size.

## Real-data provenance

- Security memory comes from [ThreatCluster threat-incident-clusters](https://huggingface.co/datasets/threatcluster/threat-incident-clusters), a dataset of incidents reported by multiple distinct outlets. The seed script selects records with at least two sources and incident-related terms, keeps the dataset’s title and summary, and records the dataset URL, cluster ID, source count, and reporting date as metadata. Licensed CC BY 4.0; attribution is required. The dataset card notes that titles and summaries are model-generated and not human-verified; treat those records as sourced reporting summaries, not ground truth.
- The sample logs come from [LogHub BGL](https://github.com/logpai/loghub), a public Blue Gene/L system-log dataset. The app does not invent or label a selected sample as a particular outage. LogHub’s repository requests research/academic use and citation; consult its current terms and citation guidance before other use.

## Operational notes

- Provider credentials are loaded only from `.env` / environment variables; no API secret is embedded in the app or browser.
- Groq calls use `openai/gpt-oss-120b`, a 700-token output ceiling, and one retry after a short delay. Rate-limit and oversized-request errors are returned as friendly UI messages.
- Hindsight recall failure is shown as a memory-service error rather than silently presenting a memory-grounded answer without memory. The stateless answer remains independently available.
- Markdown is rendered with marked.js and sanitized with DOMPurify before insertion into the page.
