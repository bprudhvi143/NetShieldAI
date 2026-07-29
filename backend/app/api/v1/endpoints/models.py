from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from app.services.auth_service import RoleChecker
from app.models.user import User
from app.services.model_info_service import model_info_service

router = APIRouter()

@router.get("/info", response_model=List[Dict[str, Any]])
def get_trained_models_info(
    current_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Retrieve real details, parameters, file metadata, and evaluation metrics for all trained ML models.
    """
    return model_info_service.get_all_models()
