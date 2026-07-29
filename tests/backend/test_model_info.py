import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_models_info_unauthenticated():
    response = client.get("/api/v1/models/info")
    # Should require authentication header
    assert response.status_code in (401, 403)

def test_model_info_service_directly():
    from app.services.model_info_service import model_info_service
    models = model_info_service.get_all_models()
    assert isinstance(models, list)
    assert len(models) >= 6
    
    cicids_if = next((m for m in models if m["id"] == "cicids2017_isolation_forest"), None)
    assert cicids_if is not None
    assert cicids_if["dataset"] == "CICIDS2017"
    assert cicids_if["feature_count"] == 77
    assert cicids_if["exists"] is True
    
    # Check metrics existence on evaluated models
    assert "accuracy" in cicids_if["metrics"]
    assert cicids_if["metrics"]["accuracy"] > 0.0

    xgb_bin = next((m for m in models if m["id"] == "cicids2017_xgboost_binary"), None)
    assert xgb_bin is not None
    assert xgb_bin["metrics"]["accuracy"] > 0.95
