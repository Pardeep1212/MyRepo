
import pytest
import asyncio
import json
from unittest.mock import patch, MagicMock, AsyncMock
import agent

from agent import InputValidator, LLMService, IncidentProcessor, IncidentRequest, IncidentResponse, CatalogIntegration, AuditLogger, ErrorHandler, app

# For FastAPI endpoint tests
from fastapi.testclient import TestClient

@pytest.fixture
def valid_incident_payload():
    return {
        "incident_description": "Database server is down, affecting multiple applications.",
        "impact": "High",
        "urgency": "High",
        "configuration_context": "Prod DB Cluster",
        "service_context": "Core Banking"
    }

@pytest.fixture
def valid_incident_request(valid_incident_payload):
    return IncidentRequest(**valid_incident_payload)

@pytest.mark.asyncio
async def test_validate_input_with_valid_payload(valid_incident_payload):
    """Unit: InputValidator.validate_input returns validated dict for valid input."""
    validator = InputValidator()
    result = validator.validate_input(valid_incident_payload)
    assert isinstance(result, dict)
    for k, v in valid_incident_payload.items():
        assert result[k] == v

def test_validate_input_with_missing_required_field():
    """Unit: InputValidator.validate_input raises ValidationError if required field missing."""
    payload = {
        # "incident_description" missing
        "impact": "High",
        "urgency": "High",
        "configuration_context": "Prod DB Cluster",
        "service_context": "Core Banking"
    }
    validator = InputValidator()
    with pytest.raises(agent.ValidationError) as excinfo:
        validator.validate_input(payload)
    assert "incident_description" in str(excinfo.value)

def test_llmservice_get_llm_client_with_missing_api_key(monkeypatch):
    """Unit: LLMService._get_llm_client raises ValueError if AZURE_OPENAI_API_KEY not set."""
    monkeypatch.setattr(agent.Config, "AZURE_OPENAI_API_KEY", None)
    llm_service = LLMService()
    with pytest.raises(ValueError) as excinfo:
        llm_service._get_llm_client()
    assert "AZURE_OPENAI_API_KEY" in str(excinfo.value)

@pytest.mark.asyncio
async def test_classify_incident_end_to_end_happy_path(valid_incident_payload):
    """Integration: IncidentProcessor.classify_incident returns success=True for valid input."""
    # Patch CatalogIntegration.fetch_catalog_details, LLMService.invoke_llm, AuditLogger.log_audit_entry
    fake_catalog = {
        "incident_type_taxonomy": ["Application", "Infrastructure"],
        "priority_matrix": {("High", "High"): "Critical"}
    }
    fake_llm_output = {
        "incident_type": "Infrastructure",
        "priority": "Critical",
        "confidence_score": 0.95,
        "rationale": "Incident affects core infrastructure.",
    }
    async def fake_fetch_catalog_details(self, incident_id, configuration_item, service_id):
        return fake_catalog
    async def fake_invoke_llm(self, system_prompt, user_prompt, few_shot_examples, incident_context):
        return {"llm_raw_output": json.dumps(fake_llm_output)}
    async def fake_log_audit_entry(self, incident_id, classification_decision, rationale):
        return True

    with patch.object(CatalogIntegration, "fetch_catalog_details", new=fake_fetch_catalog_details), \
         patch.object(LLMService, "invoke_llm", new=fake_invoke_llm), \
         patch.object(AuditLogger, "log_audit_entry", new=fake_log_audit_entry):
        processor = IncidentProcessor()
        result = await processor.classify_incident(**valid_incident_payload)
        assert result["success"] is True
        assert result["incident_type"] == "Infrastructure"
        assert result["priority"] == "Critical"
        assert result["confidence_score"] == 0.95
        assert result["rationale"]
        assert result["audit_log_entry"] == "logged"
        assert result["fallback"] is False
        assert result["error"] is None

@pytest.mark.asyncio
async def test_classify_incident_with_low_confidence_triggers_fallback(valid_incident_payload):
    """Integration: classify_incident returns fallback if confidence_score < 0.7."""
    fake_catalog = {"incident_type_taxonomy": ["Application"], "priority_matrix": {}}
    fake_llm_output = {
        "incident_type": "Application",
        "priority": "Medium",
        "confidence_score": 0.5,
        "rationale": "Uncertain classification."
    }
    async def fake_fetch_catalog_details(self, incident_id, configuration_item, service_id):
        return fake_catalog
    async def fake_invoke_llm(self, system_prompt, user_prompt, few_shot_examples, incident_context):
        return {"llm_raw_output": json.dumps(fake_llm_output)}
    async def fake_log_audit_entry(self, incident_id, classification_decision, rationale):
        return True

    with patch.object(CatalogIntegration, "fetch_catalog_details", new=fake_fetch_catalog_details), \
         patch.object(LLMService, "invoke_llm", new=fake_invoke_llm), \
         patch.object(AuditLogger, "log_audit_entry", new=fake_log_audit_entry):
        processor = IncidentProcessor()
        result = await processor.classify_incident(**valid_incident_payload)
        assert result["success"] is False
        assert result["fallback"] is True
        assert result["error"] is not None
        assert "Insufficient information" in result["error"] or "escalate" in result["error"]

def test_classify_endpoint_returns_correct_incident_response(valid_incident_payload):
    """Functional: /classify endpoint returns valid IncidentResponse for valid request."""
    client = TestClient(app)
    # Patch agent.IncidentClassificationAgent.process to return a valid IncidentResponse
    fake_response = IncidentResponse(
        success=True,
        incident_type="Infrastructure",
        priority="Critical",
        confidence_score=0.95,
        rationale="Incident affects core infrastructure.",
        audit_log_entry="logged",
        fallback=False,
        error=None
    )
    with patch.object(agent.IncidentClassificationAgent, "process", new=AsyncMock(return_value=fake_response)):
        resp = client.post("/classify", json=valid_incident_payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["incident_type"] == "Infrastructure"
        assert data["priority"] == "Critical"
        assert data["confidence_score"] == 0.95
        assert data["rationale"]
        assert data["audit_log_entry"] == "logged"
        assert data["fallback"] is False
        assert data["error"] is None

def test_classify_endpoint_with_invalid_json_returns_422():
    """Functional: /classify endpoint returns 422 for malformed JSON."""
    client = TestClient(app)
    # Send invalid JSON (missing closing brace)
    resp = client.post("/classify", data='{"incident_description": "test", "impact": "High", "urgency": "High"')
    assert resp.status_code == 422 or resp.status_code == 400
    data = resp.json()
    assert "Malformed JSON" in data.get("error", "") or "invalid request" in data.get("error", "").lower()

@pytest.mark.asyncio
async def test_classify_incident_with_empty_incident_description(valid_incident_payload):
    """Edge: classify_incident returns fallback and error if incident_description is empty."""
    payload = dict(valid_incident_payload)
    payload["incident_description"] = ""
    processor = IncidentProcessor()
    result = await processor.classify_incident(**payload)
    assert result["success"] is False
    assert result["fallback"] is True
    assert "Incident description must not be empty" in str(result["error"])

@pytest.mark.asyncio
async def test_classify_incident_llm_returns_malformed_output(valid_incident_payload):
    """Edge: classify_incident handles LLM output that cannot be parsed as JSON/YAML."""
    fake_catalog = {"incident_type_taxonomy": ["Application"], "priority_matrix": {}}
    # LLM returns output that is not JSON/YAML and does not contain expected keys
    async def fake_fetch_catalog_details(self, incident_id, configuration_item, service_id):
        return fake_catalog
    async def fake_invoke_llm(self, system_prompt, user_prompt, few_shot_examples, incident_context):
        return {"llm_raw_output": "This is not valid JSON or YAML and has no keys"}
    async def fake_log_audit_entry(self, incident_id, classification_decision, rationale):
        return True

    with patch.object(CatalogIntegration, "fetch_catalog_details", new=fake_fetch_catalog_details), \
         patch.object(LLMService, "invoke_llm", new=fake_invoke_llm), \
         patch.object(AuditLogger, "log_audit_entry", new=fake_log_audit_entry):
        processor = IncidentProcessor()
        result = await processor.classify_incident(**valid_incident_payload)
        assert result["success"] is False
        assert result["fallback"] is True
        assert "LLM output could not be parsed" in str(result["error"])

@pytest.mark.asyncio
async def test_classify_incident_catalog_returns_none(valid_incident_payload):
    """Edge: classify_incident handles None returned from fetch_catalog_details."""
    async def fake_fetch_catalog_details(self, incident_id, configuration_item, service_id):
        return None
    async def fake_invoke_llm(self, system_prompt, user_prompt, few_shot_examples, incident_context):
        # Should not be called, but if so, return valid output
        return {"llm_raw_output": json.dumps({
            "incident_type": "Application",
            "priority": "Medium",
            "confidence_score": 0.8,
            "rationale": "Fallback"
        })}
    async def fake_log_audit_entry(self, incident_id, classification_decision, rationale):
        return True

    with patch.object(CatalogIntegration, "fetch_catalog_details", new=fake_fetch_catalog_details), \
         patch.object(LLMService, "invoke_llm", new=fake_invoke_llm), \
         patch.object(AuditLogger, "log_audit_entry", new=fake_log_audit_entry):
        processor = IncidentProcessor()
        result = await processor.classify_incident(**valid_incident_payload)
        assert result["success"] is False
        assert result["fallback"] is True
        assert "CATALOG_ERROR" in str(result["error"])