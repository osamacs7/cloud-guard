from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "cloud-guard"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"

    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = ["http://localhost:3000"]

    secret_key: str = "CHANGE-ME"
    access_token_expire_minutes: int = 30
    algorithm: str = "HS256"

    database_url: str = "postgresql://cloudguard:cloudguard@localhost:5432/cloudguard"
    redis_url: str = "redis://localhost:6379/0"

    aws_profile: str = "default"
    aws_default_region: str = "us-east-1"

    azure_subscription_id: str = ""
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""

    gcp_project_id: str = ""

    slack_webhook_url: str = ""
    pagerduty_api_key: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email_from: str = "alerts@cloudguard.local"
    alert_email_to: str = ""

    scan_timeout_seconds: int = 3600
    max_concurrent_scans: int = 5

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False}


settings = Settings()
