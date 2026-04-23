
import os
import logging
from dotenv import load_dotenv

# Load .env file FIRST before any os.getenv() calls
load_dotenv()

class Config:
    _kv_secrets = {}

    # Key Vault secret mapping (only relevant entries for this agent)
    KEY_VAULT_SECRET_MAP = [
        # LLM API keys
        ("AZURE_OPENAI_API_KEY", "openai-secrets.gpt-4.1"),
        ("AZURE_OPENAI_API_KEY", "openai-secrets.azure-key"),
        ("OPENAI_API_KEY", "aba-openai-secret.openai_api_key"),
        ("ANTHROPIC_API_KEY", "anthropic-secrets.anthropic_api_key"),
        ("GOOGLE_API_KEY", "google-secrets.google_api_key"),
        # Azure Content Safety
        ("AZURE_CONTENT_SAFETY_ENDPOINT", "azure-content-safety-secrets.azure_content_safety_endpoint"),
        ("AZURE_CONTENT_SAFETY_KEY", "azure-content-safety-secrets.azure_content_safety_key"),
        # Observability DB
        ("OBS_AZURE_SQL_SERVER", "agentops-secrets.obs_sql_endpoint"),
        ("OBS_AZURE_SQL_DATABASE", "agentops-secrets.obs_azure_sql_database"),
        ("OBS_AZURE_SQL_PORT", "agentops-secrets.obs_port"),
        ("OBS_AZURE_SQL_USERNAME", "agentops-secrets.obs_sql_username"),
        ("OBS_AZURE_SQL_PASSWORD", "agentops-secrets.obs_sql_password"),
        ("OBS_AZURE_SQL_SCHEMA", "agentops-secrets.obs_azure_sql_schema"),
        # Agent identity
        ("AGENT_NAME", "agentops-secrets.agent_name"),
        ("AGENT_ID", "agentops-secrets.agent_id"),
        ("PROJECT_NAME", "agentops-secrets.project_name"),
        ("PROJECT_ID", "agentops-secrets.project_id"),
        ("SERVICE_NAME", "agentops-secrets.service_name"),
        ("SERVICE_VERSION", "agentops-secrets.service_version"),
        # LLM Model config
        ("LLM_MODEL", "agentops-secrets.llm_model"),
        ("LLM_MODELS", "agentops-secrets.llm_models"),
        # Validation config path (optional, domain-specific)
        ("VALIDATION_CONFIG_PATH", "agentops-secrets.validation_config_path"),
    ]

    # Models that do NOT support temperature/max_tokens
    _MAX_TOKENS_UNSUPPORTED = {
        "gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-5.1-chat",
        "o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o3-pro", "o4-mini"
    }
    _TEMPERATURE_UNSUPPORTED = {
        "gpt-5", "gpt-5-mini", "gpt-5-nano", "gpt-5.1-chat",
        "o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o3-pro", "o4-mini"
    }

    @classmethod
    def _load_keyvault_secrets(cls):
        """Load secrets from Azure Key Vault if enabled."""
        if not getattr(cls, "USE_KEY_VAULT", False):
            return {}
        if not getattr(cls, "KEY_VAULT_URI", ""):
            return {}
        try:
            AZURE_USE_DEFAULT_CREDENTIAL = getattr(cls, "AZURE_USE_DEFAULT_CREDENTIAL", False)
            if AZURE_USE_DEFAULT_CREDENTIAL:
                from azure.identity import DefaultAzureCredential
                credential = DefaultAzureCredential()
            else:
                from azure.identity import ClientSecretCredential
                tenant_id = os.getenv("AZURE_TENANT_ID", "")
                client_id = os.getenv("AZURE_CLIENT_ID", "")
                client_secret = os.getenv("AZURE_CLIENT_SECRET", "")
                if not (tenant_id and client_id and client_secret):
                    logging.warning("Service Principal credentials incomplete. Key Vault access will fail.")
                    return {}
                credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
            from azure.keyvault.secrets import SecretClient
            client = SecretClient(vault_url=cls.KEY_VAULT_URI, credential=credential)
            # Group refs by secret name
            by_secret = {}
            for field_name, secret_ref in getattr(cls, "KEY_VAULT_SECRET_MAP", []):
                if "." in secret_ref:
                    secret_name, json_key = secret_ref.split(".", 1)
                else:
                    secret_name, json_key = secret_ref, None
                by_secret.setdefault(secret_name, []).append((field_name, json_key))
            for secret_name, refs in by_secret.items():
                try:
                    secret = client.get_secret(secret_name)
                    if not secret or not secret.value:
                        logging.debug(f"Key Vault: secret '{secret_name}' is empty or missing")
                        continue
                    raw_value = secret.value.lstrip('\ufeff')
                    has_json_key = any(json_key is not None for _, json_key in refs)
                    if has_json_key:
                        import json as _json
                        try:
                            data = _json.loads(raw_value)
                        except Exception:
                            data = None
                        if not isinstance(data, dict):
                            logging.debug(f"Key Vault: secret '{secret_name}' value is not a JSON object")
                            continue
                        for field_name, json_key in refs:
                            if json_key is not None:
                                val = data.get(json_key)
                                if field_name in cls._kv_secrets:
                                    continue
                                if val is not None and val != "":
                                    cls._kv_secrets[field_name] = str(val)
                                else:
                                    logging.debug(f"Key Vault: key '{json_key}' not found in secret '{secret_name}' (field {field_name})")
                    else:
                        for field_name, json_key in refs:
                            if json_key is None and raw_value:
                                cls._kv_secrets[field_name] = raw_value
                                break
                except Exception as exc:
                    logging.debug(f"Key Vault: failed to fetch secret '{secret_name}': {exc}")
                    continue
        except Exception as exc:
            logging.warning(f"Key Vault: failed to connect or load secrets: {exc}")
        return cls._kv_secrets

    @classmethod
    def _validate_api_keys(cls):
        provider = getattr(cls, "MODEL_PROVIDER", "").lower()
        if provider == "openai":
            if not getattr(cls, "OPENAI_API_KEY", ""):
                raise ValueError("OPENAI_API_KEY is required for OpenAI provider")
        elif provider == "azure":
            if not getattr(cls, "AZURE_OPENAI_API_KEY", ""):
                raise ValueError("AZURE_OPENAI_API_KEY is required for Azure OpenAI provider")
            if not getattr(cls, "AZURE_OPENAI_ENDPOINT", ""):
                raise ValueError("AZURE_OPENAI_ENDPOINT is required for Azure OpenAI provider")
        elif provider == "anthropic":
            if not getattr(cls, "ANTHROPIC_API_KEY", ""):
                raise ValueError("ANTHROPIC_API_KEY is required for Anthropic provider")
        elif provider == "google":
            if not getattr(cls, "GOOGLE_API_KEY", ""):
                raise ValueError("GOOGLE_API_KEY is required for Google provider")

    @classmethod
    def get_llm_kwargs(cls):
        kwargs = {}
        model_lower = (getattr(cls, "LLM_MODEL", "") or "").lower()
        if not any(model_lower.startswith(m) for m in cls._TEMPERATURE_UNSUPPORTED):
            kwargs["temperature"] = getattr(cls, "LLM_TEMPERATURE", None)
        if any(model_lower.startswith(m) for m in cls._MAX_TOKENS_UNSUPPORTED):
            kwargs["max_completion_tokens"] = getattr(cls, "LLM_MAX_TOKENS", None)
        else:
            kwargs["max_tokens"] = getattr(cls, "LLM_MAX_TOKENS", None)
        return kwargs

    @classmethod
    def validate(cls):
        cls._validate_api_keys()

def _initialize_config():
    # Load Key Vault settings from .env
    USE_KEY_VAULT = os.getenv("USE_KEY_VAULT", "").lower() in ("true", "1", "yes")
    KEY_VAULT_URI = os.getenv("KEY_VAULT_URI", "")
    AZURE_USE_DEFAULT_CREDENTIAL = os.getenv("AZURE_USE_DEFAULT_CREDENTIAL", "").lower() in ("true", "1", "yes")

    Config.USE_KEY_VAULT = USE_KEY_VAULT
    Config.KEY_VAULT_URI = KEY_VAULT_URI
    Config.AZURE_USE_DEFAULT_CREDENTIAL = AZURE_USE_DEFAULT_CREDENTIAL

    # Load secrets from Key Vault if enabled
    if USE_KEY_VAULT:
        Config._load_keyvault_secrets()

    # Azure AI Search variables (always from .env, never Key Vault)
    AZURE_SEARCH_VARS = [
        "AZURE_SEARCH_ENDPOINT",
        "AZURE_SEARCH_API_KEY",
        "AZURE_SEARCH_INDEX_NAME"
    ]
    # Service Principal variables (conditionally skipped)
    AZURE_SP_VARS = [
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET"
    ]

    # All config variables required by agent and observability
    CONFIG_VARIABLES = [
        # General
        "ENVIRONMENT",
        # Key Vault/Service Principal
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        # LLM / Model
        "MODEL_PROVIDER",
        "LLM_MODEL",
        "LLM_MODELS",
        "LLM_TEMPERATURE",
        "LLM_MAX_TOKENS",
        "AZURE_OPENAI_ENDPOINT",
        # API Keys
        "OPENAI_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        # Azure Content Safety
        "AZURE_CONTENT_SAFETY_ENDPOINT",
        "AZURE_CONTENT_SAFETY_KEY",
        "CONTENT_SAFETY_ENABLED",
        "CONTENT_SAFETY_SEVERITY_THRESHOLD",
        # Agent identity
        "AGENT_NAME",
        "AGENT_ID",
        "PROJECT_NAME",
        "PROJECT_ID",
        "SERVICE_NAME",
        "SERVICE_VERSION",
        # Observability DB
        "OBS_DATABASE_TYPE",
        "OBS_AZURE_SQL_SERVER",
        "OBS_AZURE_SQL_DATABASE",
        "OBS_AZURE_SQL_PORT",
        "OBS_AZURE_SQL_USERNAME",
        "OBS_AZURE_SQL_PASSWORD",
        "OBS_AZURE_SQL_SCHEMA",
        "OBS_AZURE_SQL_TRUST_SERVER_CERTIFICATE",
        # Domain-specific
        "VALIDATION_CONFIG_PATH",
    ]

    # Add LLM_MODELS as a JSON list if present
    # Always skip Service Principal vars if using DefaultAzureCredential
    for var_name in CONFIG_VARIABLES:
        if var_name in AZURE_SP_VARS and AZURE_USE_DEFAULT_CREDENTIAL:
            continue
        value = None
        # Azure AI Search variables always from .env
        if var_name in AZURE_SEARCH_VARS:
            value = os.getenv(var_name)
        # Standard priority: Key Vault > .env
        elif USE_KEY_VAULT and var_name in Config._kv_secrets:
            value = Config._kv_secrets[var_name]
        else:
            value = os.getenv(var_name)
        # Special handling for LLM_MODELS (JSON list)
        if var_name == "LLM_MODELS":
            import json as _json
            if value:
                try:
                    value = _json.loads(value)
                except Exception:
                    logging.warning(f"Invalid JSON for LLM_MODELS in .env file")
                    value = []
            else:
                value = []
        # Convert numeric values to proper types
        if value and var_name == "LLM_TEMPERATURE":
            try:
                value = float(value)
            except ValueError:
                logging.warning(f"Invalid float value for {var_name}: {value}")
        elif value and var_name == "LLM_MAX_TOKENS":
            try:
                value = int(value)
            except ValueError:
                logging.warning(f"Invalid integer value for {var_name}: {value}")
        elif value and var_name == "OBS_AZURE_SQL_PORT":
            try:
                value = int(value)
            except ValueError:
                logging.warning(f"Invalid integer value for {var_name}: {value}")
        elif var_name == "OBS_AZURE_SQL_TRUST_SERVER_CERTIFICATE":
            # This variable defaults to "yes" if not found
            if not value:
                value = "yes"
        # If not found, log warning and set to "" (except LLM_MODELS which is [])
        if value is None or (isinstance(value, str) and value.strip() == ""):
            if var_name == "OBS_AZURE_SQL_TRUST_SERVER_CERTIFICATE":
                value = "yes"
            elif var_name == "LLM_MODELS":
                value = []
            else:
                logging.warning(f"Configuration variable {var_name} not found in .env file")
                value = "" if var_name != "LLM_MODELS" else []
        setattr(Config, var_name, value)

# Initialize config at module import
_initialize_config()

# Settings instance (backward compatibility with observability module)
settings = Config()
