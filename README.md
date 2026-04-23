# Enterprise IT Incident Classification & Prioritization Agent

Automated agent for classifying and prioritizing IT incidents using LLMs, with audit logging, confidence scoring, and observability. Provides a FastAPI interface for structured, standards-compliant incident triage and prioritization.

---

## Quick Start

### 1. Create a virtual environment:
```
python -m venv .venv
```

### 2. Activate the virtual environment:

**Windows:**
```
.venv\Scripts\activate
```

**macOS/Linux:**
```
source .venv/bin/activate
```

### 3. Install dependencies:
```
pip install -r requirements.txt
```

### 4. Environment setup:
Copy `.env.example` to `.env` and fill in all required values.
```
cp .env.example .env
```

### 5. Running the agent

- **Direct execution:**
  ```
  python code/agent.py
  ```

- **As a FastAPI server:**
  ```
  uvicorn code.agent:app --reload --host 0.0.0.0 --port 8000
  ```

---

## Environment Variables

**Agent Identity**
- `AGENT_NAME`
- `AGENT_ID`
- `PROJECT_NAME`
- `PROJECT_ID`
- `SERVICE_NAME`
- `SERVICE_VERSION`

**General**
- `ENVIRONMENT`

**Azure Key Vault (optional for production)**
- `USE_KEY_VAULT`
- `KEY_VAULT_URI`
- `AZURE_USE_DEFAULT_CREDENTIAL`
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`
- `AZURE_CLIENT_SECRET`

**LLM Configuration**
- `MODEL_PROVIDER`
- `LLM_MODEL`
- `LLM_MODELS` (JSON list)
- `LLM_TEMPERATURE`
- `LLM_MAX_TOKENS`
- `OPENAI_API_KEY`
- `AZURE_OPENAI_API_KEY`
- `AZURE_OPENAI_ENDPOINT`
- `ANTHROPIC_API_KEY`
- `GOOGLE_API_KEY`

**Azure Content Safety**
- `AZURE_CONTENT_SAFETY_ENDPOINT`
- `AZURE_CONTENT_SAFETY_KEY`
- `CONTENT_SAFETY_ENABLED`
- `CONTENT_SAFETY_SEVERITY_THRESHOLD`

**Observability Database (Azure SQL)**
- `OBS_DATABASE_TYPE`
- `OBS_AZURE_SQL_SERVER`
- `OBS_AZURE_SQL_DATABASE`
- `OBS_AZURE_SQL_PORT`
- `OBS_AZURE_SQL_USERNAME`
- `OBS_AZURE_SQL_PASSWORD`
- `OBS_AZURE_SQL_SCHEMA`
- `OBS_AZURE_SQL_TRUST_SERVER_CERTIFICATE`

**Agent-Specific**
- `VALIDATION_CONFIG_PATH`

**Azure AI Search (optional, for RAG)**
- `AZURE_SEARCH_ENDPOINT`
- `AZURE_SEARCH_API_KEY`
- `AZURE_SEARCH_INDEX_NAME`

---

## API Endpoints

### **GET** `/health`
- **Description:** Health check endpoint.
- **Response:**
  ```
  {
    "status": "ok"
  }
  ```

---

### **POST** `/classify`
- **Description:** Classify and prioritize an IT incident.
- **Request body:**
  ```
  {
    "incident_description": "string (required, max 50000 chars)",
    "impact": "string (required)",
    "urgency": "string (required)",
    "configuration_context": "string (optional)",
    "service_context": "string (optional)"
  }
  ```
- **Response:**
  ```
  {
    "success": true|false,
    "incident_type": "string|null",
    "priority": "string|null",
    "confidence_score": float|null,
    "rationale": "string|null",
    "audit_log_entry": "string|null",
    "fallback": true|false,
    "error": "string|null"
  }
  ```

---

## Running Tests

### 1. Install test dependencies (if not already installed):
```
pip install pytest pytest-asyncio
```

### 2. Run all tests:
```
pytest tests/
```

### 3. Run a specific test file:
```
pytest tests/test_<module_name>.py
```

### 4. Run tests with verbose output:
```
pytest tests/ -v
```

### 5. Run tests with coverage report:
```
pip install pytest-cov
pytest tests/ --cov=code --cov-report=term-missing
```

---

## Deployment with Docker

### 1. Prerequisites: Ensure Docker is installed and running.

### 2. Environment setup: Copy `.env.example` to `.env` and configure all required environment variables.

### 3. Build the Docker image:
```
docker build -t enterprise-it-incident-agent -f deploy/Dockerfile .
```

### 4. Run the Docker container:
```
docker run -d --env-file .env -p 8000:8000 --name enterprise-it-incident-agent enterprise-it-incident-agent
```

### 5. Verify the container is running:
```
docker ps
```

### 6. View container logs:
```
docker logs enterprise-it-incident-agent
```

### 7. Stop the container:
```
docker stop enterprise-it-incident-agent
```

---

## Notes

- All run commands must use the `code/` prefix (e.g., `python code/agent.py`, `uvicorn code.agent:app ...`).
- See `.env.example` for all required and optional environment variables.
- The agent requires access to LLM API keys and (optionally) Azure SQL for observability.
- For production, configure Key Vault and secure credentials as needed.

---

**Enterprise IT Incident Classification & Prioritization Agent** — Automated, standards-based IT incident triage and prioritization with LLM-powered auditability.