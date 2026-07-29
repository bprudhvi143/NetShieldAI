from fastapi import APIRouter
from app.api.v1.endpoints import auth, users, datasets, monitoring, alerts, incidents, models

# Define the root v1 router
api_router = APIRouter()

# Register resource sub-routers
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(datasets.router, prefix="/datasets", tags=["datasets"])
api_router.include_router(monitoring.router, prefix="/monitoring", tags=["monitoring"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
api_router.include_router(models.router, prefix="/models", tags=["models"])

