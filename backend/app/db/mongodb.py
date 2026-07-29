from pymongo import MongoClient
from app.config.settings import settings

# Initialize the MongoClient. This object is thread-safe and acts as a connection pool automatically.
client = MongoClient(settings.MONGO_URI)

# Select the target MongoDB database
db = client[settings.MONGO_DB]

def get_mongo_db():
    """
    Dependency helper to retrieve the MongoDB database object.
    It can be injected into FastAPI endpoints.
    """
    return db
