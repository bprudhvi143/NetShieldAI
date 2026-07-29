import os
from pydantic_settings import BaseSettings

# Dynamically resolve the absolute path to the .env file in the backend folder
current_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(os.path.dirname(current_dir))
env_path = os.path.join(backend_dir, ".env")

class Settings(BaseSettings):
    PROJECT_NAME: str
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    POSTGRES_HOST: str
    POSTGRES_PORT: int
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str

    MONGO_URI: str
    MONGO_DB: str

    ALERT_MIN_THREAT_SCORE: float = 0.0
    ALERT_MIN_RISK_LEVEL: str = "Low"
    ALERT_ON_ANOMALY_ONLY: bool = False
    ALERT_ON_INTRUSION_ONLY: bool = True
    ALERT_ON_CONFIRMED_ATTACK: bool = True
    ALERT_DEDUPLICATION_WINDOW_SECONDS: int = 300
    ALERT_AUTO_CREATE_INCIDENTS: bool = False

    LIVE_MODEL_PROFILE: str = "cicids2017"
    FLOW_IDLE_TIMEOUT_SECONDS: float = 5.0
    FLOW_RETENTION_DAYS: int = 30

    class Config:
        env_file = env_path


settings = Settings()