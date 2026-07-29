from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import logging

from app.db.postgres import get_db, SessionLocal
from app.db.mongodb import get_mongo_db
from app.services.auth_service import RoleChecker, log_audit_event
from app.models.user import User
from app.models.network_flow import NetworkFlow
from app.schemas.network_flow import NetworkFlowRead

from app.services.packet_capture_service import packet_capture_service
from app.services.flow_aggregation_service import flow_aggregation_service
from app.services.live_detection_service import live_detection_service
from app.services.websocket_manager import websocket_manager

logger = logging.getLogger("app.api.monitoring")
router = APIRouter()

@router.get("/interfaces", response_model=List[str])
def get_capture_interfaces(
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Expose discovered network interfaces on the host system.
    """
    return packet_capture_service.get_interfaces()

@router.post("/start")
def start_packet_monitoring(
    request: Request,
    interface: Optional[str] = None,
    db: Session = Depends(get_db),
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Start packet capture sniffing, flow aggregation, and live inference services.
    Logs audit event and requires Security Admin or Security Analyst role.
    """
    # Validation: Verify interface is discovered
    available = packet_capture_service.get_interfaces()
    if interface and interface != "Emulator-Interface" and interface not in available:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Selected interface '{interface}' is not available on this host. Discovered: {available}"
        )
        
    status_info = packet_capture_service.get_status()
    if status_info["status"] in ["STARTING", "RUNNING"]:
        return {"message": "Packet capture and ML pipeline is already active."}
        
    # Start Capture Layer
    packet_capture_service.start_capture(interface)
    
    # Start Flow Aggregator
    flow_aggregation_service.start()
    
    # Start ML Ingestion Layer
    try:
        live_detection_service.start()
    except Exception as ml_err:
        # Rollback capture/aggregation if pipeline setup crashes (e.g. metadata/model file missing)
        packet_capture_service.stop_capture()
        flow_aggregation_service.stop()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initialize ML detection pipeline: {ml_err}"
        )
    
    # Log starting audit event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        user_id=analyst_user.id,
        action="PACKET_MONITORING_STARTED",
        details=f"Packet sniffer and ML live analysis started on interface: {interface or 'default'}.",
        ip_address=client_ip
    )
    
    # Broadcast configuration update
    websocket_manager.broadcast({
        "event_type": "monitoring.status",
        "event_id": f"evt-status-{int(datetime.now(timezone.utc).timestamp())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": get_monitoring_status_payload()
    })
    
    return {"message": "Packet capture sniffer and ML pipeline started successfully."}

@router.post("/stop")
def stop_packet_monitoring(
    request: Request,
    db: Session = Depends(get_db),
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Stop active packet capture sniffing, aggregation, and ML processing.
    Logs audit event and requires Security Admin or Security Analyst role.
    """
    status_info = packet_capture_service.get_status()
    if status_info["status"] == "STOPPED":
        return {"message": "Monitoring services are not currently running."}
        
    packet_capture_service.stop_capture()
    flow_aggregation_service.stop()
    live_detection_service.stop()
    
    # Log stopping audit event
    client_ip = request.client.host if request.client else None
    log_audit_event(
        db=db,
        user_id=analyst_user.id,
        action="PACKET_MONITORING_STOPPED",
        details="Real-time packet capture and threat monitoring services stopped.",
        ip_address=client_ip
    )
    
    # Broadcast configuration update
    websocket_manager.broadcast({
        "event_type": "monitoring.status",
        "event_id": f"evt-status-{int(datetime.now(timezone.utc).timestamp())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": get_monitoring_status_payload()
    })
    
    return {"message": "Packet capture and threat monitoring terminated."}

def get_monitoring_status_payload() -> dict:
    cap_status = packet_capture_service.get_status()
    avg_latency = 0.0
    if live_detection_service.processed_count > 0:
        avg_latency = live_detection_service.sum_latency_ms / live_detection_service.processed_count
        
    return {
        "is_running": cap_status["status"] == "RUNNING",
        "status": cap_status["status"],
        "interface": cap_status["interface"],
        "is_emulated": cap_status["is_emulated"],
        "error_message": cap_status["error_message"],
        "started_at": cap_status["started_at"],
        "packets_captured": cap_status["packets_captured"],
        "dropped_packets": cap_status["dropped_packets"],
        "packet_queue_size": cap_status["queue_size"],
        "flows_processed": flow_aggregation_service.flows_processed,
        "dropped_flows": flow_aggregation_service.dropped_flows,
        "flow_queue_size": flow_aggregation_service.completed_flow_queue.qsize(),
        "threats_detected": live_detection_service.threats_detected,
        "average_inference_latency_ms": round(avg_latency, 2),
        "last_inference_latency_ms": round(live_detection_service.last_latency_ms, 2)
    }

@router.get("/status")
def get_monitoring_status(
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Fetch the sniffer engine's running status and metrics.
    Requires Security Admin or Security Analyst role.
    """
    return get_monitoring_status_payload()

@router.get("/packets")
def get_captured_packets(
    skip: int = 0,
    limit: int = 100,
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Retrieve logs of raw captured network packets from MongoDB.
    Sorted descending by timestamp. Supports pagination.
    """
    mongo_db = get_mongo_db()
    packets_cursor = mongo_db["captured_packets"].find({}).sort("timestamp", -1).skip(skip).limit(limit)
    
    packets = []
    for p in packets_cursor:
        packets.append({
            "id": str(p["_id"]),
            "src_ip": p["src_ip"],
            "dst_ip": p["dst_ip"],
            "protocol": p.get("protocol", "TCP"),
            "size": p.get("size", 64),
            "timestamp": p["timestamp"].isoformat() if isinstance(p["timestamp"], datetime) else str(p["timestamp"])
        })
    return packets

@router.get("/summary")
def get_traffic_summary(
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Traffic Summary API.
    Performs aggregation queries on MongoDB to compile bandwidth, protocols, and top hosts.
    Requires Security Admin or Security Analyst role.
    """
    mongo_db = get_mongo_db()
    collection = mongo_db["captured_packets"]
    
    total_pipeline = [
        {
            "$group": {
                "_id": None,
                "total_packets": {"$sum": 1},
                "total_bytes": {"$sum": "$size"},
                "avg_packet_size": {"$avg": "$size"}
            }
        }
    ]
    total_results = list(collection.aggregate(total_pipeline))
    if not total_results:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "avg_packet_size": 0,
            "protocol_distribution": [],
            "top_talkers": [],
            "top_targets": []
        }
        
    totals = total_results[0]
    
    proto_pipeline = [
        {
            "$group": {
                "_id": "$protocol",
                "count": {"$sum": 1},
                "total_bytes": {"$sum": "$size"}
            }
        },
        {"$sort": {"count": -1}}
    ]
    proto_results = list(collection.aggregate(proto_pipeline))
    protocol_distribution = []
    for r in proto_results:
        protocol_distribution.append({
            "protocol": r["_id"],
            "count": int(r["count"]),
            "total_bytes": int(r["total_bytes"]),
            "packet_percentage": round((r["count"] / totals["total_packets"]) * 100, 2),
            "bytes_percentage": round((r["total_bytes"] / totals["total_bytes"]) * 100, 2)
        })
        
    talkers_pipeline = [
        {
            "$group": {
                "_id": "$src_ip",
                "count": {"$sum": 1},
                "total_bytes": {"$sum": "$size"}
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    talkers_results = list(collection.aggregate(talkers_pipeline))
    top_talkers = [{"ip": r["_id"], "packet_count": int(r["count"]), "total_bytes": int(r["total_bytes"])} for r in talkers_results]
    
    targets_pipeline = [
        {
            "$group": {
                "_id": "$dst_ip",
                "count": {"$sum": 1},
                "total_bytes": {"$sum": "$size"}
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    targets_results = list(collection.aggregate(targets_pipeline))
    top_targets = [{"ip": r["_id"], "packet_count": int(r["count"]), "total_bytes": int(r["total_bytes"])} for r in targets_results]
    
    return {
        "total_packets": int(totals["total_packets"]),
        "total_bytes": int(totals["total_bytes"]),
        "avg_packet_size": round(float(totals["avg_packet_size"]), 2),
        "protocol_distribution": protocol_distribution,
        "top_talkers": top_talkers,
        "top_targets": top_targets
    }

@router.get("/flows", response_model=List[NetworkFlowRead])
def query_flows(
    skip: int = 0,
    limit: int = 100,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    signal_status: Optional[str] = None,
    attack_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    priority: Optional[str] = None,
    dataset_profile: Optional[str] = None,
    db: Session = Depends(get_db),
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Search and filter PostgreSQL records of processed network flows.
    """
    stmt = select(NetworkFlow)
    
    if src_ip:
        stmt = stmt.where(NetworkFlow.source_ip == src_ip)
    if dst_ip:
        stmt = stmt.where(NetworkFlow.destination_ip == dst_ip)
    if protocol:
        stmt = stmt.where(NetworkFlow.protocol == protocol)
    if signal_status:
        stmt = stmt.where(NetworkFlow.signal_status == signal_status)
    if attack_type:
        stmt = stmt.where(NetworkFlow.attack_type == attack_type)
    if risk_level:
        stmt = stmt.where(NetworkFlow.risk_level == risk_level)
    if priority:
        stmt = stmt.where(NetworkFlow.priority == priority)
    if dataset_profile:
        stmt = stmt.where(NetworkFlow.dataset_profile == dataset_profile)
        
    stmt = stmt.order_by(NetworkFlow.captured_at.desc()).offset(skip).limit(limit)
    return db.execute(stmt).scalars().all()

@router.get("/metrics")
def get_realtime_metrics(
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Expose metrics for system health (queue usage, latency, packets).
    """
    return get_monitoring_status_payload()

@router.get("/summary")
def get_traffic_summary(
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Expose traffic summary data.
    """
    return get_monitoring_status_payload()

@router.get("/timeline")
def get_timeline_data(
    db: Session = Depends(get_db),
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Exposes recent threat versus normal traffic timeline plots.
    """
    # Group flows by status in the last 1 minute / 10s intervals
    stmt = (
        select(
            NetworkFlow.signal_status,
            func.count(NetworkFlow.id).label("count")
        )
        .group_by(NetworkFlow.signal_status)
    )
    rows = db.execute(stmt).all()
    return {r[0]: r[1] for r in rows}

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = None):
    """
    WebSocket endpoint for streaming real-time flow and alert events.
    Queries the token param to validate the Security Analyst or Security Admin roles.
    """
    if not token:
        token = websocket.query_params.get("token")
        
    if not token:
        logger.warning("WebSocket connection rejected: Missing JWT token.")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    db = SessionLocal()
    try:
        from app.services.auth_service import get_current_user
        # Manually invoke dependency to authenticate token
        user = get_current_user(db=db, token=token)
        if user.role.name not in ["Security Admin", "Security Analyst"]:
            logger.warning(f"WebSocket auth rejected: User {user.email} lacks clearance.")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        # Register connection
        await websocket_manager.connect(websocket)
        
        # Keep client connection open
        while True:
            try:
                await websocket.receive_text()
            except WebSocketDisconnect:
                break
            except Exception:
                await asyncio.sleep(1)
            
    except WebSocketDisconnect:
        logger.info("WebSocket connection disconnected by client.")
    except Exception as e:
        logger.warning(f"WebSocket authentication or execution failed: {e}")
        try:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass
    finally:
        db.close()
        websocket_manager.disconnect(websocket)
