import asyncio
import asyncio as _asyncio

import time as _time
from observability.observability_wrapper import (
    trace_agent, trace_step, trace_step_sync, trace_model_call, trace_tool_call,
)
from config import settings as _obs_settings

import logging as _obs_startup_log
from contextlib import asynccontextmanager
from observability.instrumentation import initialize_tracer

_obs_startup_logger = _obs_startup_log.getLogger(__name__)

from modules.guardrails.content_safety_decorator import with_content_safety

GUARDRAILS_CONFIG = {
    'content_safety_enabled': True,
    'runtime_enabled': True,
    'content_safety_severity_threshold': 3,
    'check_toxicity': True,
    'check_jailbreak': True,
    'check_pii_input': False,
    'check_credentials_output': True,
    'check_output': True,
    'check_toxic_code_output': True,
    'sanitize_pii': False
}

import logging
import json
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError, field_validator
from pathlib import Path

from config import Config

# =========================
# SYSTEM PROMPT CONSTANTS
# =========================
SYSTEM_PROMPT = (
    "You are an expert workflow architect specializing in Enterprise IT Incident Management. "
    "Your task is to generate a comprehensive, production-ready workflow specification for "
    "\"Incident Classification & Prioritization.\" The workflow must:\n\n"
    "- Define agent roles for incident categorization and priority assessment.\n\n"
    "- Specify classification taxonomies (application, infrastructure, network, security, etc.).\n\n"
    "- Establish rules for determining priority based on impact, urgency, and business context.\n\n"
    "- Include mechanisms for confidence scoring and fallback logic when classifications are uncertain.\n\n"
    "- Detail integration points with configuration and service catalogs.\n\n"
    "- Provide output structures for classified incident records.\n\n"
    "- Ensure all classification decisions are auditable.\n\n"
    "The specification must enforce consistency, repeatability, and alignment with IT service management standards. "
    "Output should be structured, clear, and actionable. If information is insufficient, recommend escalation to a human analyst and log the incident for follow-up."
)
OUTPUT_FORMAT = (
    "- Structured YAML or JSON format with clearly defined sections for roles, taxonomies, rules, scoring, integrations, outputs, and auditability.\n\n"
    "- Include rationale and explanations for each classification and prioritization decision.\n\n"
    "- Provide fallback recommendations for uncertain or ambiguous cases."
)
FALLBACK_RESPONSE = (
    "Insufficient information is available to confidently classify or prioritize this incident. "
    "Please escalate to a human analyst for manual review and ensure the incident is logged for follow-up."
)

VALIDATION_CONFIG_PATH = Config.VALIDATION_CONFIG_PATH or str(Path(__file__).parent / "validation_config.json")

# =========================
# Observability Lifespan
# =========================
@asynccontextmanager
async def _obs_lifespan(application):
    """Initialise observability on startup, clean up on shutdown."""
    try:
        _obs_startup_logger.info('')
        _obs_startup_logger.info('========== Agent Configuration Summary ==========')
        _obs_startup_logger.info(f'Environment: {getattr(Config, "ENVIRONMENT", "N/A")}')
        _obs_startup_logger.info(f'Agent: {getattr(Config, "AGENT_NAME", "N/A")}')
        _obs_startup_logger.info(f'Project: {getattr(Config, "PROJECT_NAME", "N/A")}')
        _obs_startup_logger.info(f'LLM Provider: {getattr(Config, "MODEL_PROVIDER", "N/A")}')
        _obs_startup_logger.info(f'LLM Model: {getattr(Config, "LLM_MODEL", "N/A")}')
        _cs_endpoint = getattr(Config, 'AZURE_CONTENT_SAFETY_ENDPOINT', None)
        _cs_key = getattr(Config, 'AZURE_CONTENT_SAFETY_KEY', None)
        if _cs_endpoint and _cs_key:
            _obs_startup_logger.info('Content Safety: Enabled (Azure Content Safety)')
            _obs_startup_logger.info(f'Content Safety Endpoint: {_cs_endpoint}')
        else:
            _obs_startup_logger.info('Content Safety: Not Configured')
        _obs_startup_logger.info('Observability Database: Azure SQL')
        _obs_startup_logger.info(f'Database Server: {getattr(Config, "OBS_AZURE_SQL_SERVER", "N/A")}')
        _obs_startup_logger.info(f'Database Name: {getattr(Config, "OBS_AZURE_SQL_DATABASE", "N/A")}')
        _obs_startup_logger.info('===============================================')
        _obs_startup_logger.info('')
    except Exception as _e:
        _obs_startup_logger.warning('Config summary failed: %s', _e)

    _obs_startup_logger.info('')
    _obs_startup_logger.info('========== Content Safety & Guardrails ==========')
    if GUARDRAILS_CONFIG.get('content_safety_enabled'):
        _obs_startup_logger.info('Content Safety: Enabled')
        _obs_startup_logger.info(f'  - Severity Threshold: {GUARDRAILS_CONFIG.get("content_safety_severity_threshold", "N/A")}')
        _obs_startup_logger.info(f'  - Check Toxicity: {GUARDRAILS_CONFIG.get("check_toxicity", False)}')
        _obs_startup_logger.info(f'  - Check Jailbreak: {GUARDRAILS_CONFIG.get("check_jailbreak", False)}')
        _obs_startup_logger.info(f'  - Check PII Input: {GUARDRAILS_CONFIG.get("check_pii_input", False)}')
        _obs_startup_logger.info(f'  - Check Credentials Output: {GUARDRAILS_CONFIG.get("check_credentials_output", False)}')
    else:
        _obs_startup_logger.info('Content Safety: Disabled')
    _obs_startup_logger.info('===============================================')
    _obs_startup_logger.info('')

    _obs_startup_logger.info('========== Initializing Agent Services ==========')
    # 1. Observability DB schema (imports are inside function — only needed at startup)
    try:
        from observability.database.engine import create_obs_database_engine
        from observability.database.base import ObsBase
        import observability.database.models  # noqa: F401
        _obs_engine = create_obs_database_engine()
        ObsBase.metadata.create_all(bind=_obs_engine, checkfirst=True)
        _obs_startup_logger.info('✓ Observability database connected')
    except Exception as _e:
        _obs_startup_logger.warning('✗ Observability database connection failed (metrics will not be saved)')
    # 2. OpenTelemetry tracer (initialize_tracer is pre-injected at top level)
    try:
        _t = initialize_tracer()
        if _t is not None:
            _obs_startup_logger.info('✓ Telemetry monitoring enabled')
        else:
            _obs_startup_logger.warning('✗ Telemetry monitoring disabled')
    except Exception as _e:
        _obs_startup_logger.warning('✗ Telemetry monitoring failed to initialize')
    _obs_startup_logger.info('=================================================')
    _obs_startup_logger.info('')
    yield

app = FastAPI(
    title="Enterprise IT Incident Classification & Prioritization Agent",
    description="Automated agent for classifying and prioritizing IT incidents with audit logging and confidence scoring.",
    version=Config.SERVICE_VERSION if hasattr(Config, "SERVICE_VERSION") else "1.0.0",
    lifespan=_obs_lifespan
)

# =========================
# Input/Output Models
# =========================
class IncidentRequest(BaseModel):
    incident_description: str = Field(..., description="Incident description (required, max 50000 chars)")
    impact: str = Field(..., description="Incident impact (e.g., High, Medium, Low)")
    urgency: str = Field(..., description="Incident urgency (e.g., High, Medium, Low)")
    configuration_context: Optional[str] = Field(None, description="Relevant configuration context (optional)")
    service_context: Optional[str] = Field(None, description="Relevant service context (optional)")

    @field_validator('incident_description')
    @classmethod
    def validate_description(cls, v):
        if not v or not v.strip():
            raise ValueError("Incident description must not be empty.")
        if len(v) > 50000:
            raise ValueError("Incident description exceeds 50,000 characters.")
        return v.strip()

    @field_validator('impact')
    @classmethod
    def validate_impact(cls, v):
        if not v or not v.strip():
            raise ValueError("Impact must not be empty.")
        return v.strip()

    @field_validator('urgency')
    @classmethod
    def validate_urgency(cls, v):
        if not v or not v.strip():
            raise ValueError("Urgency must not be empty.")
        return v.strip()

class IncidentResponse(BaseModel):
    success: bool
    incident_type: Optional[str] = None
    priority: Optional[str] = None
    confidence_score: Optional[float] = None
    rationale: Optional[str] = None
    audit_log_entry: Optional[str] = None
    fallback: Optional[bool] = False
    error: Optional[str] = None

# =========================
# LLM Output Sanitizer
# =========================
import re as _re

_FENCE_RE = _re.compile(r"```(?:\w+)?\s*\n(.*?)```", _re.DOTALL)
_LONE_FENCE_START_RE = _re.compile(r"^```\w*$")
_WRAPPER_RE = _re.compile(
    r"^(?:"
    r"Here(?:'s| is)(?: the)? (?:the |your |a )?(?:code|solution|implementation|result|explanation|answer)[^:]*:\s*"
    r"|Sure[!,.]?\s*"
    r"|Certainly[!,.]?\s*"
    r"|Below is [^:]*:\s*"
    r")",
    _re.IGNORECASE,
)
_SIGNOFF_RE = _re.compile(
    r"^(?:Let me know|Feel free|Hope this|This code|Note:|Happy coding|If you)",
    _re.IGNORECASE,
)
_BLANK_COLLAPSE_RE = _re.compile(r"\n{3,}")

def _strip_fences(text: str, content_type: str) -> str:
    """Extract content from Markdown code fences."""
    fence_matches = _FENCE_RE.findall(text)
    if fence_matches:
        if content_type == "code":
            return "\n\n".join(block.strip() for block in fence_matches)
        for match in fence_matches:
            fenced_block = _FENCE_RE.search(text)
            if fenced_block:
                text = text[:fenced_block.start()] + match.strip() + text[fenced_block.end():]
        return text
    lines = text.splitlines()
    if lines and _LONE_FENCE_START_RE.match(lines[0].strip()):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()

def _strip_trailing_signoffs(text: str) -> str:
    """Remove conversational sign-off lines from the end of code output."""
    lines = text.splitlines()
    while lines and _SIGNOFF_RE.match(lines[-1].strip()):
        lines.pop()
    return "\n".join(lines).rstrip()

@with_content_safety(config=GUARDRAILS_CONFIG)
def sanitize_llm_output(raw: str, content_type: str = "code") -> str:
    """
    Generic post-processor that cleans common LLM output artefacts.
    Args:
        raw: Raw text returned by the LLM.
        content_type: 'code' | 'text' | 'markdown'.
    Returns:
        Cleaned string ready for validation, formatting, or direct return.
    """
    if not raw:
        return ""
    text = _strip_fences(raw.strip(), content_type)
    text = _WRAPPER_RE.sub("", text, count=1).strip()
    if content_type == "code":
        text = _strip_trailing_signoffs(text)
    return _BLANK_COLLAPSE_RE.sub("\n\n", text).strip()

# =========================
# Input Validation Layer
# =========================
class InputValidator:
    """Validates and sanitizes incident input fields."""

    def __init__(self):
        self.logger = logging.getLogger("InputValidator")

    def validate_input(self, incident_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize input fields."""
        try:
            validated = IncidentRequest(**incident_payload)
            return validated.dict()
        except ValidationError as ve:
            self.logger.error(f"Input validation error: {ve}")
            raise

# =========================
# Catalog Integration Layer
# =========================
class CatalogIntegration:
    """Retrieves configuration and service catalog details for incident context."""

    def __init__(self):
        self.logger = logging.getLogger("CatalogIntegration")

    async def fetch_catalog_details(
        self,
        incident_id: Optional[str],
        configuration_item: Optional[str],
        service_id: Optional[str]
    ) -> Dict[str, Any]:
        """
        Simulate retrieval of catalog details.
        In production, this would call an external API/service.
        """
        _t0 = _time.time()
        # Simulate external call latency
        await self._simulate_latency()
        details = {
            "incident_id": incident_id,
            "configuration_item": configuration_item,
            "service_id": service_id,
            "incident_type_taxonomy": ["Application", "Infrastructure", "Network", "Security", "Other"],
            "priority_matrix": {
                ("High", "High"): "Critical",
                ("High", "Medium"): "High",
                ("Medium", "High"): "High",
                ("Medium", "Medium"): "Medium",
                ("Low", "Low"): "Low"
            }
        }
        try:
            trace_tool_call(
                tool_name="CatalogIntegration.fetch_catalog_details",
                latency_ms=int((_time.time() - _t0) * 1000),
                args={"incident_id": incident_id, "configuration_item": configuration_item, "service_id": service_id},
                output=str(details)[:200],
                status="success"
            )
        except Exception:
            pass
        return details

    async def _simulate_latency(self):
        await asyncio.sleep(0.05)

# =========================
# LLM Service Layer
# =========================
class LLMService:
    """LLM orchestrator for classification/prioritization."""

    def __init__(self):
        self.logger = logging.getLogger("LLMService")
        self._client = None

    def _get_llm_client(self):
        if self._client is not None:
            return self._client
        api_key = Config.AZURE_OPENAI_API_KEY
        if not api_key:
            raise ValueError("AZURE_OPENAI_API_KEY not configured")
        import openai
        self._client = openai.AsyncAzureOpenAI(
            api_key=api_key,
            api_version="2024-02-01",
            azure_endpoint=Config.AZURE_OPENAI_ENDPOINT,
        )
        return self._client

    @with_content_safety(config=GUARDRAILS_CONFIG)
    async def invoke_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        few_shot_examples: List[str],
        incident_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calls Azure OpenAI GPT-4.1 with prompt, business rules, and examples.
        """
        _t0 = _time.time()
        client = self._get_llm_client()
        model = Config.LLM_MODEL or "gpt-4.1"
        _llm_kwargs = Config.get_llm_kwargs()
        # Build messages
        messages = [
            {"role": "system", "content": f"{system_prompt}\n\nOutput Format: {OUTPUT_FORMAT}"},
        ]
        # Add few-shot examples as user/assistant pairs
        for example in few_shot_examples:
            messages.append({"role": "user", "content": example})
        # Add user prompt with incident context
        context_str = json.dumps(incident_context, ensure_ascii=False, indent=2)
        messages.append({"role": "user", "content": f"{user_prompt}\n\nIncident Context:\n{context_str}"})
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=messages,
                **_llm_kwargs
            )
            content = response.choices[0].message.content
            try:
                trace_model_call(
                    provider="azure",
                    model_name=model,
                    prompt_tokens=getattr(getattr(response, "usage", None), "prompt_tokens", 0) or 0,
                    completion_tokens=getattr(getattr(response, "usage", None), "completion_tokens", 0) or 0,
                    latency_ms=int((_time.time() - _t0) * 1000),
                    response_summary=content[:200] if content else "",
                )
            except Exception:
                pass
            return {"llm_raw_output": content}
        except Exception as e:
            self.logger.error(f"LLM API error: {e}")
            raise

# =========================
# Audit Logging Layer
# =========================
class AuditLogger:
    """Logs classification/prioritization decisions and rationale."""

    def __init__(self):
        self.logger = logging.getLogger("AuditLogger")

    async def log_audit_entry(self, incident_id: Optional[str], classification_decision: Dict[str, Any], rationale: str) -> bool:
        """
        Simulate audit logging.
        In production, this would write to an audit log system.
        """
        _t0 = _time.time()
        entry = {
            "incident_id": incident_id,
            "decision": classification_decision,
            "rationale": rationale
        }
        # Simulate latency
        await self._simulate_latency()
        try:
            trace_tool_call(
                tool_name="AuditLogger.log_audit_entry",
                latency_ms=int((_time.time() - _t0) * 1000),
                args={"incident_id": incident_id},
                output=str(entry)[:200],
                status="success"
            )
        except Exception:
            pass
        self.logger.info(f"Audit log entry: {entry}")
        return True

    async def _simulate_latency(self):
        await asyncio.sleep(0.02)

# =========================
# Error Handling Layer
# =========================
class ErrorHandler:
    """Handles errors, manages retries, fallback logic, and escalation."""

    def __init__(self):
        self.logger = logging.getLogger("ErrorHandler")

    async def handle_error(self, error_type: str, incident_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Centralized error handling with fallback/escalation.
        """
        self.logger.error(f"Error occurred: {error_type} | Context: {incident_context}")
        # Fallback: escalate to human analyst, log for follow-up
        return {
            "success": False,
            "incident_type": None,
            "priority": None,
            "confidence_score": None,
            "rationale": FALLBACK_RESPONSE,
            "audit_log_entry": None,
            "fallback": True,
            "error": error_type
        }

# =========================
# Incident Processing Layer
# =========================
class IncidentProcessor:
    """Coordinates classification, prioritization, confidence scoring, integration, and audit logging."""

    def __init__(self):
        self.validator = InputValidator()
        self.catalog = CatalogIntegration()
        self.llm = LLMService()
        self.audit = AuditLogger()
        self.error_handler = ErrorHandler()
        self.logger = logging.getLogger("IncidentProcessor")

    @with_content_safety(config=GUARDRAILS_CONFIG)
    async def classify_incident(
        self,
        incident_description: str,
        impact: str,
        urgency: str,
        configuration_context: Optional[str] = None,
        service_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Classifies incident type, assigns priority, confidence score, and rationale.
        """
        # Step 1: Validate input
        async with trace_step(
            "validate_input", step_type="parse",
            decision_summary="Validate and sanitize incident input",
            output_fn=lambda r: f"validated={bool(r)}"
        ) as step:
            try:
                validated = self.validator.validate_input({
                    "incident_description": incident_description,
                    "impact": impact,
                    "urgency": urgency,
                    "configuration_context": configuration_context,
                    "service_context": service_context
                })
                step.capture(validated)
            except Exception as ve:
                step.capture({"error": str(ve)})
                return await self.error_handler.handle_error("VALIDATION_ERROR", {"error": str(ve)})

        # Step 2: Fetch catalog details (simulate parallel lookups)
        async with trace_step(
            "fetch_catalog_details", step_type="tool_call",
            decision_summary="Retrieve configuration/service catalog context",
            output_fn=lambda r: f"catalog_keys={list(r.keys()) if isinstance(r, dict) else '?'}"
        ) as step:
            try:
                catalog_details = await self.catalog.fetch_catalog_details(
                    incident_id=None,
                    configuration_item=configuration_context,
                    service_id=service_context
                )
                step.capture(catalog_details)
            except Exception as ce:
                step.capture({"error": str(ce)})
                return await self.error_handler.handle_error("CATALOG_ERROR", {"error": str(ce)})

        # Step 3: LLM classification/prioritization
        async with trace_step(
            "invoke_llm", step_type="llm_call",
            decision_summary="Classify and prioritize incident using LLM",
            output_fn=lambda r: f"llm_output={str(r)[:100]}"
        ) as step:
            try:
                incident_context = {
                    "incident_description": validated["incident_description"],
                    "impact": validated["impact"],
                    "urgency": validated["urgency"],
                    "configuration_context": validated.get("configuration_context"),
                    "service_context": validated.get("service_context"),
                    "catalog_details": catalog_details
                }
                few_shot_examples = [
                    "Incident: \"Database server is down, affecting multiple applications.\" Impact: High Urgency: High\nincident_type: Infrastructure\npriority: Critical\nconfidence_score: 0.95\nrationale: \"Incident affects core infrastructure and multiple business applications; immediate response required.\"",
                    "Incident: \"User unable to access email.\" Impact: Low Urgency: Medium\nincident_type: Application\npriority: Medium\nconfidence_score: 0.85\nrationale: \"Incident impacts a single user and a non-critical application; standard response time applies.\""
                ]
                user_prompt = (
                    "Please provide the incident description, impact, urgency, and any relevant configuration or service context. "
                    "The agent will classify the incident, assign a priority, and log the decision for audit purposes."
                )
                llm_result = await self.llm.invoke_llm(
                    system_prompt=SYSTEM_PROMPT,
                    user_prompt=user_prompt,
                    few_shot_examples=few_shot_examples,
                    incident_context=incident_context
                )
                raw_llm_output = llm_result.get("llm_raw_output", "")
                sanitized_output = sanitize_llm_output(raw_llm_output, content_type="code")
                step.capture({"llm_output": sanitized_output[:200]})
            except Exception as le:
                step.capture({"error": str(le)})
                return await self.error_handler.handle_error("LLM_ERROR", {"error": str(le)})

        # Step 4: Parse LLM output and extract fields
        async with trace_step(
            "parse_llm_output", step_type="parse",
            decision_summary="Parse LLM output and extract classification fields",
            output_fn=lambda r: f"parsed={bool(r)}"
        ) as step:
            try:
                # Try to parse as JSON or YAML
                parsed = self._parse_llm_output(sanitized_output)
                if not parsed:
                    raise ValueError("LLM output could not be parsed.")
                step.capture(parsed)
            except Exception as pe:
                step.capture({"error": str(pe)})
                return await self.error_handler.handle_error("LLM_OUTPUT_PARSE_ERROR", {"error": str(pe)})

        # Step 5: Fallback/escalation if confidence is low or missing
        confidence_score = None
        try:
            confidence_score = float(parsed.get("confidence_score", 0))
        except Exception:
            confidence_score = None
        fallback = False
        if confidence_score is None or confidence_score < 0.7:
            fallback = True

        # Step 6: Audit logging
        async with trace_step(
            "log_audit_entry", step_type="tool_call",
            decision_summary="Log classification/prioritization decision",
            output_fn=lambda r: f"audit_logged={r}"
        ) as step:
            try:
                audit_logged = await self.audit.log_audit_entry(
                    incident_id=None,
                    classification_decision=parsed,
                    rationale=parsed.get("rationale", "")
                )
                step.capture(audit_logged)
            except Exception as ae:
                step.capture({"error": str(ae)})
                # Do not fail the response if audit log fails

        # Step 7: Assemble response
        response = {
            "success": not fallback,
            "incident_type": parsed.get("incident_type"),
            "priority": parsed.get("priority"),
            "confidence_score": confidence_score,
            "rationale": parsed.get("rationale"),
            "audit_log_entry": "logged" if audit_logged else None,
            "fallback": fallback,
            "error": None if not fallback else FALLBACK_RESPONSE
        }
        return response

    def _parse_llm_output(self, output: str) -> Dict[str, Any]:
        """
        Attempts to parse LLM output as JSON or YAML, fallback to key-value extraction.
        """
        import yaml
        # Try JSON
        try:
            return json.loads(output)
        except Exception:
            pass
        # Try YAML
        try:
            return yaml.safe_load(output)
        except Exception:
            pass
        # Fallback: key-value extraction
        result = {}
        for line in output.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                if key in {"incident_type", "priority", "confidence_score", "rationale"}:
                    result[key] = val
        return result

# =========================
# API Layer
# =========================
class IncidentAPI:
    """API endpoint for incident classification."""

    def __init__(self, processor: IncidentProcessor):
        self.processor = processor
        self.logger = logging.getLogger("IncidentAPI")

    @with_content_safety(config=GUARDRAILS_CONFIG)
    async def classify(self, req: IncidentRequest) -> IncidentResponse:
        async with trace_step(
            "api_classify", step_type="process",
            decision_summary="API endpoint for incident classification",
            output_fn=lambda r: f"success={r.get('success', False)}"
        ) as step:
            try:
                result = await self.processor.classify_incident(
                    incident_description=req.incident_description,
                    impact=req.impact,
                    urgency=req.urgency,
                    configuration_context=req.configuration_context,
                    service_context=req.service_context
                )
                step.capture(result)
                return IncidentResponse(**result)
            except Exception as e:
                step.capture({"error": str(e)})
                self.logger.error(f"API classify error: {e}")
                return IncidentResponse(
                    success=False,
                    error=str(e),
                    fallback=True
                )

# =========================
# Main Agent Class
# =========================
class IncidentClassificationAgent:
    """Main agent orchestrator."""

    def __init__(self):
        self.processor = IncidentProcessor()
        self.api = IncidentAPI(self.processor)
        self.error_handler = ErrorHandler()
        self.logger = logging.getLogger("IncidentClassificationAgent")

    @trace_agent(agent_name=_obs_settings.AGENT_NAME, project_name=_obs_settings.PROJECT_NAME)
    @with_content_safety(config=GUARDRAILS_CONFIG)
    async def process(self, req: IncidentRequest) -> IncidentResponse:
        return await self.api.classify(req)

# =========================
# FastAPI Endpoints
# =========================
agent = IncidentClassificationAgent()

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}

@app.post("/classify", response_model=IncidentResponse)
async def classify_endpoint(req: IncidentRequest):
    """
    Classify and prioritize an IT incident.
    """
    try:
        result = await agent.process(req)
        return result
    except ValidationError as ve:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "success": False,
                "error": f"Validation error: {ve.errors()}",
                "fix_tip": "Check required fields and ensure all values are valid."
            }
        )
    except Exception as e:
        logging.getLogger("agent").error(f"Unhandled error: {e}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "error": f"Internal server error: {str(e)}",
                "fix_tip": "Contact support with error details."
            }
        )

@app.exception_handler(RequestValidationError)
@with_content_safety(config=GUARDRAILS_CONFIG)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "success": False,
            "error": "Malformed JSON or invalid request fields.",
            "details": exc.errors(),
            "fix_tip": "Ensure your JSON is well-formed and all required fields are present."
        }
    )

@app.exception_handler(json.decoder.JSONDecodeError)
@with_content_safety(config=GUARDRAILS_CONFIG)
async def json_decode_exception_handler(request: Request, exc: json.decoder.JSONDecodeError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "success": False,
            "error": "Malformed JSON in request body.",
            "details": str(exc),
            "fix_tip": "Check for missing quotes, commas, or brackets in your JSON."
        }
    )

# =========================
# Entrypoint
# =========================
async def _run_agent():
    """Entrypoint: runs the agent with observability (trace collection only)."""
    import uvicorn

    # Unified logging config — routes uvicorn, agent, and observability through
    # the same handler so all telemetry appears in a single consistent stream.
    _LOG_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(levelprefix)s %(name)s: %(message)s",
                "use_colors": None,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "uvicorn":        {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.error":  {"level": "INFO"},
            "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
            "agent":          {"handlers": ["default"], "level": "INFO", "propagate": False},
            "__main__":       {"handlers": ["default"], "level": "INFO", "propagate": False},
            "observability": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "config": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "azure":   {"handlers": ["default"], "level": "WARNING", "propagate": False},
            "urllib3": {"handlers": ["default"], "level": "WARNING", "propagate": False},
        },
    }

    config = uvicorn.Config(
        "agent:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level="info",
        log_config=_LOG_CONFIG,
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    _asyncio.run(_run_agent())