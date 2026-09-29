import base64
from fastapi.testclient import TestClient
from types import SimpleNamespace
import pytest

import main


client = TestClient(main.app)


class FakeHindsightContext:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def test_triage_returns_stateless_and_memory_grounded_answers(monkeypatch):
    monkeypatch.setattr(
        main,
        "_recall_sync",
        lambda bank_id, query: [{"text": "Real incident: API outage. Roll back the bad deployment.", "type": "experience"}],
    )
    monkeypatch.setattr(
        main,
        "_groq_sync",
        lambda question, memories=None: "Baseline guidance." if memories is None else "Roll back the bad deployment.",
    )

    response = client.post("/api/triage", json={"question": "Our API is down after a deployment"})

    assert response.status_code == 200
    body = response.json()
    assert body["stateless"]["answer"] == "Baseline guidance."
    assert body["grounded"]["answer"] == "Roll back the bad deployment."
    assert body["recalled_count"] == 1
    assert body["memories"][0]["text"].startswith("Real incident:")


def test_preview_auth_blocks_public_access_and_allows_valid_credentials(monkeypatch):
    monkeypatch.setenv("PREVIEW_USERNAME", "preview-user")
    monkeypatch.setenv("PREVIEW_PASSWORD", "temporary-preview-password")

    unauthorized = client.get("/")
    token = base64.b64encode(b"preview-user:temporary-preview-password").decode("ascii")
    authorized = client.get("/", headers={"Authorization": f"Basic {token}"})

    assert unauthorized.status_code == 401
    assert unauthorized.headers["www-authenticate"].startswith("Basic")
    assert authorized.status_code == 200


def test_scope_guard_skips_memory_and_model_calls(monkeypatch):
    called = []
    monkeypatch.setattr(main, "_classify_scope_sync", lambda question: called.append("classifier") or False)
    monkeypatch.setattr(main, "_recall_sync", lambda *args: called.append("recall"))
    monkeypatch.setattr(main, "_groq_sync", lambda *args: called.append("groq"))

    response = client.post("/api/triage", json={"question": "Recommend a pasta recipe"})

    assert response.status_code == 200
    body = response.json()
    assert body["out_of_scope"] is True
    assert body["stateless"]["answer"] == "Out of scope: I only handle incident response."
    assert body["grounded"]["answer"] == body["stateless"]["answer"]
    assert body["recalled_count"] == 0
    assert called == ["classifier"]


def test_scope_guard_rejects_sports_score_question(monkeypatch):
    classified = []
    monkeypatch.setattr(main, "_classify_scope_sync", lambda question: classified.append(question) or False)
    monkeypatch.setattr(main, "_recall_sync", lambda *args: pytest.fail("out-of-scope recall must not run"))
    monkeypatch.setattr(main, "_groq_sync", lambda *args: pytest.fail("out-of-scope triage must not run"))

    response = client.post(
        "/api/triage",
        json={"question": "what is the score of india vs westindies"},
    )

    assert response.status_code == 200
    assert response.json()["stateless"]["answer"] == "Out of scope: I only handle incident response."
    assert classified == ["what is the score of india vs westindies"]


def test_fast_scope_pass_allows_incident_examples(monkeypatch):
    monkeypatch.setattr(main, "_classify_scope_sync", lambda question: pytest.fail("fast pass should not classify"))
    monkeypatch.setattr(main, "_recall_sync", lambda bank_id, query: [])
    monkeypatch.setattr(main, "_groq_sync", lambda question, memories=None: "General steps.")

    questions = [
        "Job fails at startup because its working directory is missing on the compute node",
        "instruction cache parity error on node R02",
        "SSL certificate expired",
        "Kafka queue compaction is failing",
    ]
    for question in questions:
        response = client.post("/api/triage", json={"question": question})
        assert response.status_code == 200
        assert response.json()["out_of_scope"] is False


def test_loghub_scenarios_return_only_matching_real_rows(monkeypatch, tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "loghub_bgl_sample.log").write_text(
        "RAS KERNEL INFO instruction cache parity error corrected\n"
        "RAS APP FATAL ciod: LOGIN chdir(/missing/path) failed\n"
        "RAS KERNEL INFO 63543 double-hummer alignment exceptions\n"
        "RAS KERNEL INFO unrelated event\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(main, "ROOT", tmp_path)

    scenarios = {
        "instruction-cache-parity": "instruction cache parity error",
        "ciod-chdir-failure": "ciod: LOGIN chdir(",
        "double-hummer-alignment": "double-hummer alignment exceptions",
    }
    for scenario, expected in scenarios.items():
        response = client.get("/api/loghub-sample", params={"scenario": scenario})

        assert response.status_code == 200
        assert response.json()["source"] == "LogHub BGL dataset"
        assert expected in response.json()["logs"]
        assert "unrelated event" not in response.json()["logs"]


def test_scope_guard_uses_classifier_when_no_incident_keyword_matches(monkeypatch):
    classified = []
    monkeypatch.setattr(main, "_classify_scope_sync", lambda question: classified.append(question) or True)

    question = "Could you investigate this unusual situation?"

    assert main._is_in_scope(question) is True
    assert classified == [question]


def test_ambiguous_database_question_uses_classifier_and_is_rejected(monkeypatch):
    classified = []
    monkeypatch.setattr(main, "_classify_scope_sync", lambda question: classified.append(question) or False)
    monkeypatch.setattr(main, "_recall_sync", lambda *args: pytest.fail("out-of-scope recall must not run"))

    response = client.post("/api/triage", json={"question": "what is database"})

    assert response.status_code == 200
    assert response.json()["stateless"]["answer"] == "Out of scope: I only handle incident response."
    assert classified == ["what is database"]


def test_greeting_and_joke_are_rejected_by_classifier(monkeypatch):
    classified = []
    monkeypatch.setattr(main, "_classify_scope_sync", lambda question: classified.append(question) or False)
    monkeypatch.setattr(main, "_recall_sync", lambda *args: pytest.fail("out-of-scope recall must not run"))

    for question in ("hi", "tell me a joke"):
        response = client.post("/api/triage", json={"question": question})
        assert response.status_code == 200
        assert response.json()["stateless"]["answer"] == "Out of scope: I only handle incident response."

    assert classified == ["hi", "tell me a joke"]


def test_scope_classifier_uses_tiny_yes_no_groq_call(monkeypatch):
    calls = []

    class FakeCompletions:
        def create(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="YES"))])

    fake_groq = SimpleNamespace(chat=SimpleNamespace(completions=FakeCompletions()))
    monkeypatch.setattr(main, "_get_groq", lambda: fake_groq)

    assert main._classify_scope_sync("what is database") is True
    assert len(calls) == 1
    assert calls[0]["max_tokens"] == 5
    assert calls[0]["temperature"] == 0
    assert calls[0]["messages"][0]["content"] == main.SCOPE_CLASSIFIER_PROMPT


def test_recall_shortens_query_after_hindsight_token_limit(monkeypatch):
    queries = []

    class FakeHindsight(FakeHindsightContext):
        def recall(self, bank_id, query, max_tokens):
            queries.append(query)
            if len(query) > 225:
                raise RuntimeError("Query too long: exceeds maximum of 500 tokens.")
            return SimpleNamespace(results=[])

    monkeypatch.setattr(main, "_get_hindsight", lambda: FakeHindsight())

    assert main._recall_sync("test-bank", "log " * 500) == []
    assert [len(query) for query in queries] == [900, 450, 225]


def test_recall_deduplicates_same_text_across_memory_types(monkeypatch):
    class FakeHindsight(FakeHindsightContext):
        def recall(self, bank_id, query, max_tokens):
            return SimpleNamespace(
                results=[
                    SimpleNamespace(text="Same outage fix.", type="world"),
                    SimpleNamespace(text=" same outage fix. ", type="observation"),
                    SimpleNamespace(text="A different fix.", type="experience"),
                ]
            )

    monkeypatch.setattr(main, "_get_hindsight", lambda: FakeHindsight())

    memories = main._recall_sync("test-bank", "outage fix")

    assert memories == [
        {"text": "Same outage fix.", "type": "world"},
        {"text": "A different fix.", "type": "experience"},
    ]


def test_evidence_text_has_no_memory_type_tags(monkeypatch):
    monkeypatch.setattr(
        main,
        "_recall_response_sync",
        lambda bank_id, query: SimpleNamespace(
            results=[
                SimpleNamespace(text="[observation] Restart the worker.", type="observation"),
                SimpleNamespace(text="[world] Check the mount.", type="world"),
            ]
        ),
    )

    memories = main._recall_sync("test-bank", "worker failure")

    assert [memory["text"] for memory in memories] == ["Restart the worker.", "Check the mount."]
    assert all("[observation]" not in memory["text"] for memory in memories)
    assert all("[world]" not in memory["text"] for memory in memories)


def test_no_memory_notice_is_hidden_from_stateless_and_shown_once_grounded(monkeypatch):
    monkeypatch.setattr(main, "_recall_sync", lambda bank_id, query: [])
    monkeypatch.setattr(
        main,
        "_groq_sync",
        lambda question, memories=None: "No relevant memory found. General triage advice. No relevant memory found.",
    )

    response = client.post("/api/triage", json={"question": "Our API is down after a deployment"})

    assert response.status_code == 200
    body = response.json()
    phrase = "no relevant memory found"
    assert phrase not in body["stateless"]["answer"].lower()
    assert body["grounded"]["answer"].lower().count(phrase) == 1
    assert "General triage advice." in body["grounded"]["answer"]


def test_approve_lesson_removes_no_memory_lines_and_headings(monkeypatch):
    retained = []

    class FakeHindsight(FakeHindsightContext):
        def retain(self, **kwargs):
            retained.append(kwargs)

    monkeypatch.setattr(main, "_get_hindsight", lambda: FakeHindsight())
    monkeypatch.setattr(main, "_recall_sync", lambda bank_id, query: [])

    response = client.post(
        "/api/lessons/approve",
        json={
            "lesson": (
                "No relevant memory found.\n\n"
                "## Triage Summary\n"
                "Triage Summary:\n"
                "Rollback the deployment when elevated 5xx errors begin immediately after release."
            )
        },
    )

    expected = "Rollback the deployment when elevated 5xx errors begin immediately after release."
    assert response.status_code == 200
    assert response.json()["lesson"] == expected
    assert len(retained) == 1
    assert retained[0]["content"] == expected


def test_approve_lesson_rejects_empty_cleaned_content_without_retaining(monkeypatch):
    retained = []

    class FakeHindsight(FakeHindsightContext):
        def retain(self, **kwargs):
            retained.append(kwargs)

    monkeypatch.setattr(main, "_get_hindsight", lambda: FakeHindsight())
    monkeypatch.setattr(main, "_recall_sync", lambda bank_id, query: [])

    response = client.post(
        "/api/lessons/approve",
        json={"lesson": "No relevant memory found.\n\n## Triage Summary\nTriage Summary:"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Lesson has no retainable content after cleanup."
    assert retained == []


def test_approve_lesson_rejects_only_no_memory_notice(monkeypatch):
    retained = []

    class FakeHindsight:
        def retain(self, **kwargs):
            retained.append(kwargs)

    monkeypatch.setattr(main, "_get_hindsight", lambda: FakeHindsight())
    monkeypatch.setattr(main, "_recall_sync", lambda bank_id, query: [])

    response = client.post(
        "/api/lessons/approve",
        json={"lesson": "No relevant memory found"},
    )

    assert response.status_code == 422
    assert retained == []


def test_approve_lesson_skips_near_duplicate(monkeypatch):
    retained = []

    class FakeHindsight:
        def retain(self, **kwargs):
            retained.append(kwargs)

    existing = "Check the NFS mount first, remount it, then resubmit the job. Do not recreate the directory."
    monkeypatch.setattr(main, "_get_hindsight", lambda: FakeHindsight())
    monkeypatch.setattr(
        main,
        "_recall_sync",
        lambda bank_id, query: [{"text": existing, "type": "experience"}],
    )

    response = client.post(
        "/api/lessons/approve",
        json={"lesson": "Check NFS mount first, remount it, then resubmit the job. Do not recreate directory."},
    )

    assert response.status_code == 409
    assert retained == []


def test_memory_prompt_separates_memory_and_general_suggestions():
    prompt = main.SYSTEM_PROMPT
    assert prompt.index("From memory") < prompt.index("General suggestions (not from memory)")
    assert "Preserve the order of steps" in prompt
    assert "No relevant memory found" in prompt


def test_no_memory_response_has_sections_and_single_notice():
    response = main._clean_no_memory_notice(
        "## From memory\nNo relevant memory found.\n\n"
        "## General suggestions (not from memory)\nCheck service health.",
        include_notice=True,
    )

    assert response.count("No relevant memory found") == 1
    assert response.index("## From memory") < response.index("## General suggestions (not from memory)")
    assert "Check service health." in response


def test_log_resolution_retains_problem_and_solution_with_distinct_source(monkeypatch):
    retained = []

    class FakeHindsight(FakeHindsightContext):
        def retain(self, **kwargs):
            retained.append(kwargs)

    monkeypatch.setattr(main, "_get_hindsight", lambda: FakeHindsight())

    response = client.post(
        "/api/resolutions/log",
        json={
            "problem": "The worker could not open its configured state directory.",
            "solution": "I restored the directory from backup and restarted the worker.",
        },
    )

    expected = (
        "Problem: The worker could not open its configured state directory.\n"
        "Solution: I restored the directory from backup and restarted the worker."
    )
    assert response.status_code == 200
    assert response.json() == {"logged": True, "entry": expected}
    assert len(retained) == 1
    assert retained[0]["content"] == expected
    assert retained[0]["context"] == "engineer-logged resolution"
    assert retained[0]["metadata"] == {"source": "engineer-logged resolution"}


def test_log_resolution_rejects_whitespace_only_fields(monkeypatch):
    monkeypatch.setattr(main, "_get_hindsight", lambda: pytest.fail("invalid resolutions must not be retained"))

    response = client.post(
        "/api/resolutions/log",
        json={"problem": "           ", "solution": "A real solution that should not be retained."},
    )

    assert response.status_code == 422


def test_memory_explorer_labels_retention_source(monkeypatch):
    class FakeHindsight(FakeHindsightContext):
        def list_memories(self, bank_id, limit, offset):
            return SimpleNamespace(
                items=[
                    SimpleNamespace(
                        text="Engineer resolution",
                        metadata={"source": "engineer-logged resolution"},
                    ),
                    SimpleNamespace(
                        text="Approved triage lesson",
                        metadata={"source": "IncidentOps human approval"},
                    ),
                    SimpleNamespace(
                        text="Seeded incident",
                        metadata={"source": "https://huggingface.co/datasets/threatcluster/threat-incident-clusters"},
                    ),
                ],
                total=3,
            )

    monkeypatch.setattr(main, "_get_hindsight", lambda: FakeHindsight())

    response = client.get("/api/memories")

    assert response.status_code == 200
    assert [item["source_label"] for item in response.json()["items"]] == [
        "engineer-logged",
        "approved from triage",
        "real-data seed",
    ]
