from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config.settings import settings
from app.api.v1.api import api_router
from app.db.postgres import Base, engine, SessionLocal
from app.models.role import Role
from app.models.user import User
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.alert_history import AlertHistory
from app.models.incident_history import IncidentHistory
from app.models.network_flow import NetworkFlow
from app.core.security import get_password_hash
from app.services.auth_service import log_audit_event

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0"
)

# Enable CORS for frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Startup event handler to initialize the database and seed default values
@app.on_event("startup")
def startup_db_setup():
    # Set event loop on WebSocket ConnectionManager
    import asyncio
    from app.services.websocket_manager import websocket_manager
    websocket_manager.set_event_loop(asyncio.get_running_loop())

    # Automatically create tables in PostgreSQL
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # 1. Seed Roles if empty
        roles_count = db.query(Role).count()
        if roles_count == 0:
            print("No roles found in database. Seeding default roles...")
            admin_role = Role(
                name="Security Admin",
                description="System administrator with full security management access."
            )
            analyst_role = Role(
                name="Security Analyst",
                description="Security analyst with threat monitoring and packet capture access."
            )
            db.add_all([admin_role, analyst_role])
            db.commit()
            print("Successfully seeded Security Admin and Security Analyst roles.")
        
        # 2. Seed Default Users if empty
        user_count = db.query(User).count()
        if user_count == 0:
            print("No users found in database. Seeding default accounts...")
            # Fetch Roles
            admin_role_db = db.query(Role).filter(Role.name == "Security Admin").first()
            analyst_role_db = db.query(Role).filter(Role.name == "Security Analyst").first()
            
            # Create Admin
            admin_user = User(
                email="admin@netshield.ai",
                hashed_password=get_password_hash("AdminNetShield123!"),
                full_name="System Administrator",
                role_id=admin_role_db.id,
                is_active=True
            )
            db.add(admin_user)
            
            # Create Analyst
            analyst_user = User(
                email="analyst@netshield.ai",
                hashed_password=get_password_hash("AnalystNetShield123!"),
                full_name="SOC Lead Analyst",
                role_id=analyst_role_db.id,
                is_active=True
            )
            db.add(analyst_user)
            db.commit()
            
            db.refresh(admin_user)
            db.refresh(analyst_user)
            
            # Log registration events
            log_audit_event(
                db=db,
                user_id=admin_user.id,
                action="USER_REGISTERED",
                details="Initial system administration account created.",
                ip_address="127.0.0.1"
            )
            log_audit_event(
                db=db,
                user_id=analyst_user.id,
                action="USER_REGISTERED",
                details="Initial security analyst account created.",
                ip_address="127.0.0.1"
            )
            print("Default accounts successfully seeded:")
            print("  - admin@netshield.ai / AdminNetShield123!")
            print("  - analyst@netshield.ai / AnalystNetShield123!")
            
        # 3. Log System Startup
        log_audit_event(
            db=db,
            user_id=None,
            action="SYSTEM_STARTUP",
            details="NetShield AI FastAPI Backend service started successfully.",
            ip_address="127.0.0.1"
        )
        
    except Exception as e:
        print("Error checking or seeding database:", e)
    finally:
        db.close()

# Mount the main API router
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "message": "Welcome to NetShield AI",
        "project": settings.PROJECT_NAME
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "NetShield AI Backend",
        "version": "1.0.0"
    }

@app.on_event("shutdown")
def shutdown_background_services():
    print("FastAPI shutting down. Stopping background sniffing, flow aggregation, and ML pipeline...")
    from app.services.packet_capture_service import packet_capture_service
    from app.services.flow_aggregation_service import flow_aggregation_service
    from app.services.live_detection_service import live_detection_service

    packet_capture_service.stop_capture()
    flow_aggregation_service.stop()
    live_detection_service.stop()
    print("Background services successfully terminated.")