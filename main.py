"""IncidentOps FastAPI application: grounded incident triage with approved memory."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import os
import re
import time
import uuid
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from groq import Groq
from hindsight_client import Hindsight
from pydantic import BaseModel, Field, field_validator

load_dotenv()

ROOT = Path(__file__).parent
BASE_BANK_ID = "incidentops-v1"
LOGHUB_SCENARIOS = {
    "instruction-cache-parity": {
        "label": "Instruction cache parity error",
        "pattern": "instruction cache parity error",
    },
    "ciod-chdir-failure": {
        "label": "CIOD chdir failure",
        "pattern": "ciod: login chdir(",
    },
    "double-hummer-alignment": {
        "label": "Double-hummer alignment exceptions",
        "pattern": "double-hummer alignment exceptions",
    },
}
MODEL = "openai/gpt-oss-120b"
RECALL_QUERY_CHARS = 900
RECALL_QUERY_ATTEMPTS = 5
SYSTEM_PROMPT = (
    "You are IncidentOps, an incident response commander. Return exactly two Markdown sections, in this order: "
    "'## From memory' followed by '## General suggestions (not from memory)'. In From memory, include ONLY "
    "recalled lessons, quoted or closely paraphrased; never invent incidents, dates, causes, or fixes. Preserve "
    "the order of steps in recalled lessons; do not reorder them. Put all other advice, hypotheses, and commands "
    "only under General suggestions, and never present them as past lessons. If no lessons are recalled, put only "
    "'No relevant memory found' in From memory, then provide the general suggestions section. Keep the full "
    "answer concise: at most 3 relevant lessons and 3 short general actions, with complete sentences."
)
STATELESS_SYSTEM_PROMPT = (
    "You are an incident response commander. Give concise, general incident-response best practices. "
    "Do not mention memory, recalled lessons, or memory availability. Do not claim past incident experience. "
    "Give at most 4 short, complete actions; do not write an exhaustive playbook."
)
NO_MEMORY_NOTICE = re.compile(r"no relevant memory found[.!]?", re.IGNORECASE)
NO_MEMORY_LINE = re.compile(r"^\s*no relevant memory found\b", re.IGNORECASE)
MEMORY_TYPE_TAG = re.compile(r"\[(?:observation|world)\]\s*", re.IGNORECASE)
FAST_INCIDENT_TERMS = re.compile(
    r"\b(fail|fails|failed|failing|failure|error|errors|crash|crashes|crashed|crashing|"
    r"down|outage|timeout|latency|slow|degraded|unavailable|missing|expired|denied|"
    r"exception|fatal|breach|attack|leak|vulnerability|ransomware|phishing|exploit|incident|alert|"
    r"working\s+directory|compute\s+node|batch\s+job|job\s+(?:fails?|failed|failure)|"
    r"startup\s+failure|scheduler|worker\s+(?:fails?|failed|failure))\b",
    re.IGNORECASE,
)
SCOPE_CLASSIFIER_PROMPT = (
    "Is this message about an IT, infrastructure, or security incident? "
    "Answer only YES or NO."
)

app = FastAPI(title="IncidentOps", version="1.0.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
app.state.bank_id = BASE_BANK_ID


@app.middleware("http")
async def preview_auth(request, call_next):
    username = os.getenv("PREVIEW_USERNAME")
    password = os.getenv("PREVIEW_PASSWORD")
    if not username and not password:
        return await call_next(request)
    if not username or not password:
        return PlainTextResponse("Preview authentication is misconfigured.", status_code=503)

    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    try:
        credentials = base64.b64decode(token, validate=True).decode("utf-8") if scheme.lower() == "basic" else ""
    except (binascii.Error, UnicodeDecodeError, ValueError):
        credentials = ""
    supplied_username, separator, supplied_password = credentials.partition(":")
    valid = (
        bool(separator)
        and hmac.compare_digest(supplied_username, username)
        and hmac.compare_digest(supplied_password, password)
    )
    if not valid:
        return PlainTextResponse(
            "Authentication required.",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="IncidentOps preview"'},
        )
    return await call_next(request)


class QuestionRequest(BaseModel):
    question: str = Field(min_length=1, max_length=12000)


class LessonRequest(BaseModel):
    lesson: str = Field(min_length=10, max_length=5000)
    question: str = Field(default="", max_length=12000)
    answer: str = Field(default="", max_length=12000)


class ResolutionRequest(BaseModel):
    problem: str = Field(min_length=10, max_length=5000)
    solution: str = Field(min_length=10, max_length=5000)

    @field_validator("problem", "solution", mode="before")
    @classmethod
    def require_non_whitespace_content(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()
            if len(value) < 10:
                raise ValueError("Must contain at least 10 non-whitespace characters.")
        return value


class QueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000)


class IngestRequest(BaseModel):
    logs: str = Field(min_length=1, max_length=16000)


def _get_hindsight() -> Hindsight:
    base_url = os.getenv("HINDSIGHT_BASE_URL")
    if not base_url:
        raise RuntimeError("Set HINDSIGHT_BASE_URL in your .env file.")
    return Hindsight(base_url=base_url, api_key=os.getenv("HINDSIGHT_API_KEY"))


def _get_groq() -> Groq:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("Set GROQ_API_KEY in your .env file.")
    return Groq(api_key=api_key)


def _create_bank_with_client(client: Hindsight, bank_id: str) -> None:
    client.create_bank(
        bank_id=bank_id,
        name="IncidentOps",
        mission="Support incident response with evidence from approved lessons. Never invent past incidents or fixes.",
        reflect_mission="Synthesize only knowledge present in this incident-response memory bank. State when evidence is absent.",
    )


def _create_bank(bank_id: str) -> None:
    with _get_hindsight() as client:
        _create_bank_with_client(client, bank_id)


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if hasattr(value, "text"):
        return str(value.text)
    if isinstance(value, dict):
        return str(value.get("text", value.get("content", value)))
    return str(value)


def _is_in_scope(question: str) -> bool:
    if FAST_INCIDENT_TERMS.search(question):
        return True
    return _classify_scope_sync(question)


def _classify_scope_sync(question: str) -> bool:
    try:
        response = _get_groq().chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SCOPE_CLASSIFIER_PROMPT},
                {"role": "user", "content": question[:1600]},
            ],
            max_tokens=5,
            temperature=0,
        )
        answer = _text(response.choices[0].message.content).strip().upper().rstrip(".!?")
        return answer == "YES"
    except Exception:
        return False


def _recall_response_sync(bank_id: str, query: str) -> Any:
    with _get_hindsight() as client:
        bounded_query = query[:RECALL_QUERY_CHARS]
        for attempt in range(RECALL_QUERY_ATTEMPTS):
            try:
                return client.recall(bank_id=bank_id, query=bounded_query, max_tokens=1800)
            except Exception as exc:
                if "query too long" not in str(exc).lower() or len(bounded_query) <= 64:
                    raise
                if attempt == RECALL_QUERY_ATTEMPTS - 1:
                    raise
                bounded_query = bounded_query[: max(1, len(bounded_query) // 2)]
    raise RuntimeError("Hindsight recall could not fit the query token limit.")


def _recall_sync(bank_id: str, query: str) -> list[dict[str, str]]:
    response = _recall_response_sync(bank_id, query)
    results = getattr(response, "results", []) or []
    memories = []
    seen_texts = set()
    for item in results:
        full_text = MEMORY_TYPE_TAG.sub("", _text(item)).strip()
        key = " ".join(full_text.casefold().split())
        if not key or key in seen_texts:
            continue
        seen_texts.add(key)
        memories.append({"text": full_text[:300], "type": str(getattr(item, "type", "memory"))})
        if len(memories) == 5:
            break
    return memories


def _groq_sync(question: str, memories: list[dict[str, str]] | None = None) -> str:
    context = "\n".join(f"- {m['text'][:300]}" for m in (memories or []))
    if memories is None:
        user_content = question
    else:
        user_content = f"Question: {question}\n\nRecalled memories:\n{context or '(none)'}"
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            response = _get_groq().chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT if memories is not None else STATELESS_SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                max_tokens=700,
                temperature=0.2,
            )
            return _text(response.choices[0].message.content).strip() or "The model returned an empty response. Please try again."
        except Exception as exc:  # Groq SDK and provider error shapes vary by API version.
            last_error = exc
            if attempt == 0:
                time.sleep(0.6)
    message = str(last_error or "Unknown Groq error")
    if "413" in message or "429" in message or "rate_limit" in message.lower():
        raise RuntimeError("Groq is at its current request limit. Please wait a moment and retry.") from last_error
    raise RuntimeError(f"Groq could not complete this request: {message[:240]}") from last_error


def _friendly_error(exc: Exception) -> str:
    message = str(exc)
    if "413" in message or "429" in message or "request limit" in message.lower():
        return "Groq is busy or rate-limited. Please wait a moment and retry."
    return message if message else "The request could not be completed. Check your service configuration."


def _clean_no_memory_notice(answer: str, *, include_notice: bool) -> str:
    answer = NO_MEMORY_NOTICE.sub("", answer)
    answer = re.sub(r"(?m)^\s*[,;:.]+\s*", "", answer)
    answer = re.sub(r"\n{3,}", "\n\n", answer).strip()
    if include_notice:
        general_heading = re.search(
            r"(?im)^\s*#{1,6}\s*General suggestions \(not from memory\)\s*#*\s*$",
            answer,
        )
        general = answer[general_heading.end():].strip() if general_heading else answer
        general = re.sub(r"(?im)^\s*#{1,6}\s*From memory\s*#*\s*$", "", general).strip()
        return (
            "## From memory\nNo relevant memory found.\n\n"
            "## General suggestions (not from memory)\n"
            f"{general}"
        ).rstrip()
    return answer


def _clean_approved_lesson(lesson: str) -> str:
    cleaned_lines = []
    for line in lesson.splitlines():
        stripped = line.strip()
        if NO_MEMORY_LINE.match(stripped):
            continue
        if re.match(r"^#{1,6}(?:\s+|$)", stripped):
            continue
        plain_heading = stripped.strip("*_` ").rstrip(":").strip().casefold()
        if plain_heading == "triage summary":
            continue
        cleaned_lines.append(line.rstrip())
    cleaned = "\n".join(cleaned_lines)
    cleaned = re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", cleaned)
    return cleaned.strip()


def _retain_lesson_sync(bank_id: str, content: str) -> Any:
    with _get_hindsight() as client:
        return client.retain(
            bank_id=bank_id,
            content=content,
            context="human-approved incident response lesson",
            metadata={"source": "IncidentOps human approval"},
        )


def _retain_resolution_sync(bank_id: str, content: str) -> Any:
    with _get_hindsight() as client:
        return client.retain(
            bank_id=bank_id,
            content=content,
            context="engineer-logged resolution",
            metadata={"source": "engineer-logged resolution"},
        )


def _list_memories_sync(bank_id: str) -> Any:
    with _get_hindsight() as client:
        return client.list_memories(bank_id=bank_id, limit=100, offset=0)


def _reflect_sync(bank_id: str, query: str) -> Any:
    with _get_hindsight() as client:
        return client.reflect(
            bank_id=bank_id,
            query=query,
            budget="low",
            max_tokens=700,
            include_facts=True,
        )


def _is_near_duplicate(lesson: str, recalled_text: str) -> bool:
    normalize = lambda value: " ".join(value.casefold().split())
    candidate = normalize(lesson)
    recalled = normalize(recalled_text)
    if not candidate or not recalled:
        return False
    shorter, longer = sorted((candidate, recalled), key=len)
    if len(shorter) >= 80 and shorter in longer:
        return True
    return SequenceMatcher(None, candidate, recalled).ratio() >= 0.92


async def _triage(question: str, recall_query: str | None = None) -> dict[str, Any]:
    if not await asyncio.to_thread(_is_in_scope, question):
        answer = "Out of scope: I only handle incident response."
        return {
            "stateless": {"answer": answer, "latency_ms": 0, "error": None},
            "grounded": {"answer": answer, "latency_ms": 0, "error": None},
            "memories": [],
            "recalled_count": 0,
            "out_of_scope": True,
        }

    bank_id = app.state.bank_id
    recalled: list[dict[str, str]] = []
    recall_error: str | None = None
    try:
        recalled = await asyncio.to_thread(_recall_sync, bank_id, recall_query or question)
    except Exception as exc:
        recall_error = _friendly_error(exc)

    async def answer_call(memories: list[dict[str, str]] | None) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            answer = await asyncio.to_thread(_groq_sync, question, memories)
            if memories is None:
                answer = _clean_no_memory_notice(answer, include_notice=False)
            elif not memories:
                answer = _clean_no_memory_notice(answer, include_notice=True)
            return {"answer": answer, "latency_ms": round((time.perf_counter() - start) * 1000), "error": None}
        except Exception as exc:
            error = _friendly_error(exc)
            return {"answer": error, "latency_ms": round((time.perf_counter() - start) * 1000), "error": error}

    stateless, grounded = await asyncio.gather(answer_call(None), answer_call(recalled))
    if recall_error:
        grounded = {
            "answer": f"Memory service unavailable: {recall_error}",
            "latency_ms": grounded["latency_ms"],
            "error": recall_error,
        }
    return {
        "stateless": stateless,
        "grounded": grounded,
        "memories": recalled,
        "recalled_count": len(recalled),
        "out_of_scope": False,
    }


def _dump(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "dict"):
        return value.dict()
    if isinstance(value, list):
        return [_dump(item) for item in value]
    if isinstance(value, dict):
        return {key: _dump(item) for key, item in value.items()}
    if hasattr(value, "__dict__"):
        return {key: _dump(item) for key, item in vars(value).items() if not key.startswith("_")}
    return value


def _memory_source_label(item: dict[str, Any]) -> str:
    metadata = item.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    source = metadata.get("source") or item.get("source")
    context = str(item.get("context", "")).casefold()
    if source == "engineer-logged resolution" or context == "engineer-logged resolution":
        return "engineer-logged"
    if source == "IncidentOps human approval" or context == "human-approved incident response lesson":
        return "approved from triage"
    if isinstance(source, str) and "threatcluster" in source.casefold():
        return "real-data seed"
    return "other source"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (ROOT / "static" / "index.html").read_text(encoding="utf-8")


@app.get("/api/status")
def status() -> dict[str, Any]:
    hindsight_connected = False
    groq_connected = False
    if os.getenv("HINDSIGHT_BASE_URL"):
        try:
            with _get_hindsight() as hindsight:
                hindsight.get_version()
                _create_bank_with_client(hindsight, app.state.bank_id)
            hindsight_connected = True
        except Exception:
            pass
    if os.getenv("GROQ_API_KEY"):
        try:
            _get_groq().models.list()
            groq_connected = True
        except Exception:
            pass
    return {
        "bank_id": app.state.bank_id,
        "hindsight_configured": bool(os.getenv("HINDSIGHT_BASE_URL")),
        "groq_configured": bool(os.getenv("GROQ_API_KEY")),
        "hindsight_connected": hindsight_connected,
        "groq_connected": groq_connected,
    }


@app.post("/api/triage")
async def triage(request: QuestionRequest) -> dict[str, Any]:
    return await _triage(request.question.strip())


@app.post("/api/lessons/approve")
async def approve_lesson(request: LessonRequest) -> dict[str, Any]:
    content = _clean_approved_lesson(request.lesson)
    if not content:
        raise HTTPException(status_code=422, detail="Lesson has no retainable content after cleanup.")
    try:
        recalled = await asyncio.to_thread(_recall_sync, app.state.bank_id, content)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=_friendly_error(exc)) from exc
    if any(_is_near_duplicate(content, memory["text"]) for memory in recalled):
        raise HTTPException(status_code=409, detail="A nearly identical lesson already exists in memory.")
    try:
        await asyncio.to_thread(_retain_lesson_sync, app.state.bank_id, content)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=_friendly_error(exc)) from exc
    return {"approved": True, "lesson": content}


@app.post("/api/resolutions/log")
async def log_resolution(request: ResolutionRequest) -> dict[str, Any]:
    content = f"Problem: {request.problem}\nSolution: {request.solution}"
    bank_id = app.state.bank_id
    print(
        f"[log-resolution] request bank_id={bank_id!r} "
        f"problem={request.problem!r} solution={request.solution!r}",
        flush=True,
    )
    try:
        retain_response = await asyncio.to_thread(_retain_resolution_sync, bank_id, content)
        print(f"[log-resolution] retain response={retain_response!r}", flush=True)
    except Exception as exc:
        print(f"[log-resolution] retain raised {type(exc).__name__}: {exc}", flush=True)
        raise HTTPException(status_code=503, detail=_friendly_error(exc)) from exc
    return {"logged": True, "entry": content}


@app.get("/api/memories")
async def memories() -> dict[str, Any]:
    try:
        result = await asyncio.to_thread(_list_memories_sync, app.state.bank_id)
        items = _dump(result.items)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    item["source_label"] = _memory_source_label(item)
        return {
            "items": items,
            "total": result.total,
            "bank_id": app.state.bank_id,
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail=_friendly_error(exc)) from exc


@app.post("/api/recall")
async def recall(request: QueryRequest) -> dict[str, Any]:
    if not await asyncio.to_thread(_is_in_scope, request.query):
        return {"message": "Out of scope: I only handle incident response.", "results": []}
    try:
        result = await asyncio.to_thread(
            _recall_response_sync,
            app.state.bank_id,
            request.query,
        )
        return _dump(result)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=_friendly_error(exc)) from exc


@app.post("/api/reflect")
async def reflect(request: QueryRequest) -> dict[str, Any]:
    if not await asyncio.to_thread(_is_in_scope, request.query):
        return {"text": "Out of scope: I only handle incident response."}
    try:
        result = await asyncio.to_thread(_reflect_sync, app.state.bank_id, request.query)
        return _dump(result)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=_friendly_error(exc)) from exc


@app.post("/api/reset")
def reset() -> dict[str, str]:
    bank_id = f"incidentops-cold-{uuid.uuid4().hex[:12]}"
    try:
        _create_bank(bank_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=_friendly_error(exc)) from exc
    app.state.bank_id = bank_id
    return {"bank_id": bank_id, "message": "Cold Start"}


@app.post("/api/ingest")
async def ingest(request: IngestRequest) -> dict[str, Any]:
    prompt = "Triage these supplied system logs. Identify likely symptoms and immediate safe checks.\n\n" + request.logs.strip()
    return await _triage(prompt)


@app.get("/api/loghub-sample")
def loghub_sample(scenario: str | None = None) -> dict[str, str]:
    sample_path = ROOT / "data" / "loghub_bgl_sample.log"
    if not sample_path.exists():
        raise HTTPException(status_code=404, detail="LogHub sample not downloaded yet. Run python seed_real_data.py first.")
    if scenario is None:
        return {"source": "LogHub BGL dataset", "logs": sample_path.read_text(encoding="utf-8")[:12000]}
    selected = LOGHUB_SCENARIOS.get(scenario)
    if selected is None:
        raise HTTPException(status_code=404, detail="Unknown LogHub BGL scenario.")
    logs = [
        line
        for line in sample_path.read_text(encoding="utf-8").splitlines()
        if selected["pattern"] in line.casefold()
    ]
    if not logs:
        raise HTTPException(status_code=404, detail=f"No rows found for {selected['label']} in the local LogHub sample.")
    return {
        "source": "LogHub BGL dataset",
        "scenario": scenario,
        "label": selected["label"],
        "logs": "\n".join(logs),
    }
