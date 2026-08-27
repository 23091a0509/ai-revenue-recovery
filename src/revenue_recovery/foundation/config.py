"""Environment configuration and production safeguard validator for AI Revenue Recovery MVP.

Architecture Invariants Enforced:
- INV-05: Strict MVP Sandbox Isolation (Config Layer — NOTE: Invariant remains NOT PROVEN until network-level egress is implemented)
- INV-06: Zero Production Credentials / Network Paths in MVP (NOTE: Invariant remains NOT PROVEN until full credential scanning & secret management is verified)
"""

import ipaddress
import os
import re
import secrets
from typing import Any, Dict, Set
from urllib.parse import urlparse
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator


class ProductionBoundaryViolationError(ValueError):
    """Raised when a production credential, endpoint, environment, or unsafe variable is detected in MVP."""
    pass


class ConfigurationError(ValueError):
    """Raised when required configuration is missing, malformed, or unsafe."""
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

# Environment variable prefixes/names indicating live production credentials or infrastructure
FORBIDDEN_PROD_ENV_PREFIXES_OR_KEYS = [
    "STRIPE_",
    "RAZORPAY_",
    "PAYPAL_",
    "TWILIO_",
    "SENDGRID_",
    "MAILGUN_",
    "AWS_SECRET_",
    "AWS_ACCESS_KEY",
    "PROD_",
    "PRODUCTION_",
    "LIVE_",
    "STAGING_"
]

# Regex patterns matching live / production API key formats
PRODUCTION_KEY_PATTERNS = [
    re.compile(r"^sk_live_[a-zA-Z0-9]+$"),
    re.compile(r"^pk_live_[a-zA-Z0-9]+$"),
    re.compile(r"^rk_live_[a-zA-Z0-9]+$"),
    re.compile(r"^live_[a-zA-Z0-9_]+$"),
    re.compile(r"^prod_[a-zA-Z0-9_]+$"),
    re.compile(r"^sec_live_[a-zA-Z0-9]+$"),
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
]

# Strict allowlist of recognized configuration environment keys
RECOGNIZED_CONFIG_KEYS = {
    "ENVIRONMENT",
    "LLM_PROVIDER",
    "LLM_MODEL",
    "LLM_API_KEY",
    "AUTH_SIGNING_SECRET",
    "TOKEN_EXPIRY_SECONDS",
    "SANDBOX_PAYMENT_SIMULATOR_URL",
    "SANDBOX_MESSAGING_SIMULATOR_URL",
    "LOG_LEVEL",
    "AUDIT_STORAGE_PATH"
}

ALLOWED_SANDBOX_HOST_PATTERNS = [
    re.compile(r"^localhost$"),
    re.compile(r"^127\.0\.0\.1$"),
    re.compile(r"^::1$"),
    re.compile(r"^sandbox-[a-zA-Z0-9\-]+$"),
    re.compile(r"^[a-zA-Z0-9\-]+\.sandbox$"),
]


class AppSettings(BaseModel):
    """Immutable, validated application settings enforcing strict sandbox isolation."""
    
    # MVP must be explicitly and exclusively 'sandbox'
    environment: str = Field(default="sandbox")
    
    # LLM Settings
    llm_provider: str = Field(default="openai")
    llm_model: str = Field(default="gpt-4o")
    llm_api_key: str = Field(default="")
    
    # Security & Authorization (NO static default secret - must be explicitly set or generated per session)
    auth_signing_secret: str
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

    @field_validator("auth_signing_secret")
    @classmethod
    def validate_signing_secret(cls, v: str) -> str:
        if not v or not v.strip():
            raise ConfigurationError(
                "auth_signing_secret cannot be empty. An explicit sandbox signing secret is required."
            )
        v_clean = v.strip()
        if len(v_clean) < 16:
            raise ConfigurationError(
                "auth_signing_secret is too short (must be at least 16 characters for cryptographic safety)."
            )
        # Check against common static placeholder patterns
        weak_defaults = {
            "sandbox-default-signing-secret-do-not-use-in-prod",
            "default_secret",
            "secret1234567890",
            "change_this_secret",
            "password12345678"
        }
        if v_clean.lower() in weak_defaults:
            raise ConfigurationError(
                "Static weak default signing secret detected. A dedicated sandbox secret or session token must be configured."
            )
        for pat in PRODUCTION_KEY_PATTERNS:
            if pat.match(v_clean):
                raise ProductionBoundaryViolationError(
                    "Production boundary violation: Detected live/production credential format in auth_signing_secret."
                )
        return v_clean

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
        
        # Userinfo in URL is forbidden (e.g. http://localhost@api.stripe.com or http://user:pass@evil.com)
        if parsed.username or parsed.password:
            raise ProductionBoundaryViolationError(
                f"Production boundary violation: URL contains userinfo credentials '{parsed.netloc}'."
            )

        # Strip port and normalize trailing dots
        hostname = (parsed.hostname or "").rstrip(".").lower()
        if not hostname:
            raise ConfigurationError(f"Malformed simulator URL with empty hostname: '{v}'")

        # Check against explicitly forbidden production domains
        for forbidden in FORBIDDEN_PRODUCTION_DOMAINS:
            if hostname == forbidden or hostname.endswith("." + forbidden):
                raise ProductionBoundaryViolationError(
                    f"Production boundary violation: Real provider endpoint detected '{hostname}'."
                )
        
        # Handle IP addresses
        try:
            ip_obj = ipaddress.ip_address(hostname)
            if not ip_obj.is_loopback:
                raise ProductionBoundaryViolationError(
                    f"Production boundary violation: Non-loopback IP address '{hostname}' is not permitted in MVP."
                )
            return v
        except ValueError:
            # Not an IP literal, validate hostname against allowed sandbox patterns
            pass

        is_allowed = any(pat.match(hostname) for pat in ALLOWED_SANDBOX_HOST_PATTERNS)
        if not is_allowed:
            raise ProductionBoundaryViolationError(
                f"Production boundary violation: Hostname '{hostname}' is not a permitted sandbox target. "
                "Allowed hosts must match localhost, 127.0.0.1, ::1, sandbox-* or *.sandbox."
            )
        
        return v

    @field_validator("llm_api_key")
    @classmethod
    def validate_llm_api_key(cls, v: str) -> str:
        if not v:
            return v
        for pat in PRODUCTION_KEY_PATTERNS:
            if pat.match(v.strip()):
                raise ProductionBoundaryViolationError(
                    "Production boundary violation: Detected live/production credential format in llm_api_key."
                )
        return v

    @model_validator(mode="after")
    def validate_no_live_keys_in_any_field(self) -> "AppSettings":
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
        if "Invalid environment" in msg or "Malformed simulator URL" in msg or "Simulator URL cannot be empty" in msg or "auth_signing_secret" in msg:
            raise ConfigurationError(msg)
    
    raise exc


def scan_environment_for_forbidden_production_artifacts(env_dict: Dict[str, str]) -> None:
    """Scans the full environment dictionary for any unauthorized production variables or keys."""
    for key, val in env_dict.items():
        key_upper = key.upper()
        
        # Check if environment key matches known forbidden production integration prefixes
        for prefix in FORBIDDEN_PROD_ENV_PREFIXES_OR_KEYS:
            if key_upper.startswith(prefix) or key_upper == prefix.rstrip("_"):
                raise ProductionBoundaryViolationError(
                    f"Production boundary violation: Unauthorized production environment variable '{key}' detected. "
                    "MVP process environment must not contain live credentials or production configs."
                )
        
        # Scan value of any environment variable for live credentials
        if isinstance(val, str) and val.strip():
            for pat in PRODUCTION_KEY_PATTERNS:
                if pat.search(val):
                    raise ProductionBoundaryViolationError(
                        f"Production boundary violation: Environment variable '{key}' contains live production credential format."
                    )


def generate_ephemeral_sandbox_signing_secret() -> str:
    """Generates a secure random 32-character signing secret scoped to the current sandbox session."""
    return f"sandbox_session_secret_{secrets.token_hex(16)}"


_CACHED_SETTINGS: AppSettings | None = None


def load_settings_from_env(
    env_dict: Dict[str, str] | None = None,
    allow_ephemeral_secret: bool = True
) -> AppSettings:
    """Loads and validates settings with strict environment scanning and fail-closed semantics."""
    source = dict(os.environ) if env_dict is None else dict(env_dict)
    
    # 1. Scan the entire source dictionary for forbidden production variables/keys
    scan_environment_for_forbidden_production_artifacts(source)
    
    # 2. Extract recognized keys with case-insensitive mapping
    raw_config: Dict[str, Any] = {}
    for key, val in source.items():
        key_upper = key.upper()
        if key_upper in RECOGNIZED_CONFIG_KEYS:
            key_lower = key_upper.lower()
            if key_lower == "token_expiry_seconds":
                try:
                    raw_config["token_expiry_seconds"] = int(val)
                except ValueError:
                    raise ConfigurationError(f"token_expiry_seconds must be an integer, got '{val}'")
            else:
                raw_config[key_lower] = val

    # 3. Handle auth_signing_secret: if not provided and ephemeral allowed, generate sandbox session secret
    if "auth_signing_secret" not in raw_config or not raw_config["auth_signing_secret"]:
        if allow_ephemeral_secret:
            raw_config["auth_signing_secret"] = generate_ephemeral_sandbox_signing_secret()
        else:
            raise ConfigurationError("Missing required configuration: 'auth_signing_secret'")

    return AppSettings(**raw_config)


def get_settings() -> AppSettings:
    """Returns cached validated settings singleton."""
    global _CACHED_SETTINGS
    if _CACHED_SETTINGS is None:
        _CACHED_SETTINGS = load_settings_from_env()
    return _CACHED_SETTINGS


def reset_cached_settings() -> None:
    """Clears cached settings for testing isolation."""
    global _CACHED_SETTINGS
    _CACHED_SETTINGS = None
