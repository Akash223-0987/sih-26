"""
Application Configuration for FastAPI CRUD Telemetry Generator.
"""

import os
from pathlib import Path
from pydantic import BaseModel


class Settings(BaseModel):
    # App Information
    app_name: str = "Enterprise Perimeter & Threat Management API"
    app_version: str = "1.0.0"
    environment: str = os.getenv("APP_ENV", "development")
    debug: bool = os.getenv("APP_DEBUG", "true").lower() in ("true", "1", "yes")

    # Server Bindings
    host: str = os.getenv("APP_HOST", "127.0.0.1")
    port: int = int(os.getenv("APP_PORT", "8000"))

    # Database
    db_path: Path = Path(os.getenv("DB_PATH", "logs/crud_app.db"))

    # Logging & PyTrace Telemetry
    service_name: str = os.getenv("SERVICE_NAME", "perimeter-security-api")
    log_file_path: Path = Path(os.getenv("LOG_FILE_PATH", "logs/application.log"))
    enable_console_logging: bool = True
    enable_file_logging: bool = True


settings = Settings()
