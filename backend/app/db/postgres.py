from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config.settings import settings

# Construct the synchronous PostgreSQL database URL
SQLALCHEMY_DATABASE_URL = (
    f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
    f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
)

# Create the SQLAlchemy engine. We do not need connect_args={"check_same_thread": False}
# as this is only required for SQLite, not PostgreSQL.
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Create a sessionmaker factory for producing database sessions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative base class for models to inherit from
Base = declarative_base()

# Dependency to get db session in FastAPI endpoints
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
