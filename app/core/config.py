from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""

    # API Configuration
    api_key: str = Field(default="default-api-key-change-me", validation_alias="API_KEY")
    api_key_header: str = Field(default="X-API-Key", validation_alias="API_KEY_HEADER")

    # Application
    app_title: str = Field(default="Agentic Scam Honeypot API", validation_alias="APP_TITLE")
    app_version: str = Field(default="0.1.0", validation_alias="APP_VERSION")
    app_description: str = "Backend REST API for scam detection and intelligence gathering"

    # Session Management
    max_messages_per_session: int = Field(default=20, validation_alias="MAX_MESSAGES_PER_SESSION")
    session_timeout_seconds: int = Field(default=3600, validation_alias="SESSION_TIMEOUT_SECONDS")
    min_messages_for_callback: int = Field(default=3, validation_alias="MIN_MESSAGES_FOR_CALLBACK")

    # Scam Detection
    scam_confidence_threshold: float = 0.6

    # Callback
    callback_url: Optional[str] = None
    callback_timeout: int = 10

    # ✅ THIS is how .env is loaded in Pydantic v2
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8"
    )


settings = Settings()

print("Loaded API_KEY =", settings.api_key)
