"""Environment configuration and production safeguard validator for AI Revenue Recovery MVP.

Architecture Invariants Enforced:
- INV-05: Strict MVP Sandbox Isolation
- INV-06: Zero Production Credentials / Network Paths in MVP
"""

import os
import re
from typing import Any, Set
from urllib.parse import urlparse
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


class ProductionBoundaryViolationError(ValueError):
    """Raised when a production credential, endpoint, or environment is detected in MVP."""
    pass


class ConfigurationError(ValueError):
    """Raised when required configuration is missing or invalid."""
    pass


# Known production domain patterns that must NEVER be configured in MVP
FORBIDDEN_PRODUCTION_DOMAINS: Set[str] = {
    "api.stripe.com",
    "api.razorpay.com",
    "api.paypal.com",
    "api.braintreegateway.com",
    "api.adyen.com",
    "api.squareup.com",
    "api.twilio.com",
    "api.sendgrid.com",
    "api.mailgun.net",
    "graph.facebook.com",
    "api.whatsapp.com",
    "api.plaid.com",
    "api.checkout.com"
}

# Regex patterns matching live / production API key formats
PRODUCTION_KEY_PATTERNS = [
    re.compile(r"^sk_live_[a-zA-Z0-9]+$"),
    re.compile(r"^pk_live_[a-zA-Z0-9]+$"),
    re.compile(r"^rk_live_[a-zA-Z0-9]+$"),
    re.compile(r"^live_[a-zA-Z0-9_]+$"),
    re.compile(r"^prod_[a-zA-Z0-9_]+$"),
    re.compile(r"^sec_live_[a-zA-Z0-9]+$"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),  # AWS Production IAM access keys
]

ALLOWED_SANDBOX_HOST_PATTERNS = [
    re.compile(r"^localhost(:\d+)?$"),
    re.compile(r"^127\.0\.0\.1(:\d+)?$"),
    re.compile(r"^sandbox-[a-zA-Z0-9\.\-]+(:\d+)?$"),
    re.compile(r"^[a-zA-Z0-9\.\-]+\.sandbox(:\d+)?$"),
]


class AppSettings(BaseModel):
    """Immutable, validated application settings enforcing strict sandbox isolation."""
    
    # MVP must be explicitly and exclusively 'sandbox'
    environment: str = Field(default="sandbox")
    
    # LLM Settings
    llm_provider: str = Field(default="openai")
    llm_model: str = Field(default="gpt-4o")
    llm_api_key: str = Field(default="")
    
    # Security & Authorization
    auth_signing_secret: str = Field(default="sandbox-default-signing-secret-do-not-use-in-prod")
    token_expiry_seconds: int = Field(default=300, ge=30, le=3600)
    
    # Sandbox Simulators (Must be local or sandbox-scoped)
    sandbox_payment_simulator_url: str = Field(default="http://localhost:8001")
    sandbox_messaging_simulator_url: str = Field(default="http://localhost:8002")
    
    # Audit & Observability
    log_level: str = Field(default="INFO")
    audit_storage_path: str = Field(default="./logs/audit.log")

    model_config = {
        "frozen": True,
        "extra": "forbid"
    }

    def __init__(self, **data: Any):
        try:
            super().__init__(**data)
        except ValidationError as exc:
            # Re-raise custom boundary / configuration exceptions directly
            _unwrap_and_raise_validation_error(exc)

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        env_norm = v.strip().lower()
        if env_norm in ("production", "prod", "live", "mainnet", "staging"):
            raise ProductionBoundaryViolationError(
                f"Production boundary violation: MVP environment cannot run in '{v}' mode. "
                "MVP is strictly restricted to 'sandbox' mode."
            )
        if env_norm != "sandbox":
            raise ConfigurationError(
                f"Invalid environment: '{v}'. Only 'sandbox' is permitted in MVP."
            )
        return env_norm

    @field_validator("sandbox_payment_simulator_url", "sandbox_messaging_simulator_url")
    @classmethod
    def validate_simulator_endpoint(cls, v: str) -> str:
        if not v or not v.strip():
            raise ConfigurationError("Simulator URL cannot be empty.")
        
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            raise ConfigurationError(f"Malformed simulator URL: '{v}'")
        
        if parsed.scheme not in ("http", "https"):
            raise ConfigurationError(f"Unsupported URL scheme in simulator URL: '{parsed.scheme}'")
        
        hostname = parsed.netloc.lower()
        
        # Check against explicitly forbidden production domains
        for forbidden in FORBIDDEN_PRODUCTION_DOMAINS:
            if forbidden in hostname:
                raise ProductionBoundaryViolationError(
                    f"Production boundary violation: Real provider endpoint detected '{hostname}'. "
                    "MVP is forbidden from connecting to production payment or messaging systems."
                )
        
        # Check against allowed sandbox hostname patterns
        is_allowed = any(pat.match(hostname) for pat in ALLOWED_SANDBOX_HOST_PATTERNS)
        if not is_allowed:
            raise ProductionBoundaryViolationError(
                f"Production boundary violation: Hostname '{hostname}' is not a permitted sandbox target. "
                "Allowed hosts must match localhost, 127.0.0.1, or sandbox-* domains."
            )
        
        return v

    @field_validator("llm_api_key", "auth_signing_secret")
    @classmethod
    def validate_secrets_for_live_credentials(cls, v: str) -> str:
        if not v:
            return v
        for pat in PRODUCTION_KEY_PATTERNS:
            if pat.match(v.strip()):
                raise ProductionBoundaryViolationError(
                    "Production boundary violation: Detected live/production credential format in configuration. "
                    "Production credentials are strictly prohibited in the MVP environment."
                )
        return v

    @model_validator(mode="after")
    def validate_no_live_keys_in_any_field(self) -> "AppSettings":
        # Global scan of all string values for suspicious production markers
        for field_name, val in self:
            if isinstance(val, str):
                for pat in PRODUCTION_KEY_PATTERNS:
                    if pat.search(val):
                        raise ProductionBoundaryViolationError(
                            f"Production boundary violation: Field '{field_name}' contains suspicious "
                            "production-like credential format."
                        )
        return self


def _unwrap_and_raise_validation_error(exc: ValidationError) -> None:
    """Unwraps Pydantic ValidationError to re-raise underlying domain errors."""
    for err in exc.errors():
        ctx = err.get("ctx", {})
        error_obj = ctx.get("error")
        if isinstance(error_obj, (ProductionBoundaryViolationError, ConfigurationError)):
            raise error_obj
        
        msg = err.get("msg", "")
        if "Production boundary violation" in msg:
            raise ProductionBoundaryViolationError(msg)
        if "Invalid environment" in msg or "Malformed simulator URL" in msg or "Simulator URL cannot be empty" in msg:
            raise ConfigurationError(msg)
    
    raise exc


_CACHED_SETTINGS: AppSettings | None = None


def load_settings_from_env(env_dict: dict[str, str] | None = None) -> AppSettings:
    """Loads and validates settings from environment or provided dictionary with fail-closed semantics."""
    source = os.environ if env_dict is None else env_dict
    
    # Extract known keys with case-insensitive mapping
    raw_config: dict[str, Any] = {}
    for key, val in source.items():
        key_lower = key.lower()
        if key_lower == "environment":
            raw_config["environment"] = val
        elif key_lower == "llm_provider":
            raw_config["llm_provider"] = val
        elif key_lower == "llm_model":
            raw_config["llm_model"] = val
        elif key_lower == "llm_api_key":
            raw_config["llm_api_key"] = val
        elif key_lower == "auth_signing_secret":
            raw_config["auth_signing_secret"] = val
        elif key_lower == "token_expiry_seconds":
            try:
                raw_config["token_expiry_seconds"] = int(val)
            except ValueError:
                raise ConfigurationError(f"token_expiry_seconds must be an integer, got '{val}'")
        elif key_lower == "sandbox_payment_simulator_url":
            raw_config["sandbox_payment_simulator_url"] = val
        elif key_lower == "sandbox_messaging_simulator_url":
            raw_config["sandbox_messaging_simulator_url"] = val
        elif key_lower == "log_level":
            raw_config["log_level"] = val
        elif key_lower == "audit_storage_path":
            raw_config["audit_storage_path"] = val

    return AppSettings(**raw_config)


def get_settings() -> AppSettings:
    """Returns the cached validated settings singleton, loading from environment if not yet initialized."""
    global _CACHED_SETTINGS
    if _CACHED_SETTINGS is None:
        _CACHED_SETTINGS = load_settings_from_env()
    return _CACHED_SETTINGS


def reset_cached_settings() -> None:
    """Clears cached settings for testing isolation."""
    global _CACHED_SETTINGS
    _CACHED_SETTINGS = None
