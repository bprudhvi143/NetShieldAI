import React, { useState, useEffect, useRef, useMemo } from "react";
import { 
  ShieldAlert, 
  Radio, 
  Database, 
  Wifi, 
  WifiOff, 
  Activity, 
  Users, 
  Settings, 
  TrendingUp, 
  FileText, 
  AlertTriangle, 
  Play, 
  Square, 
  ShieldCheck, 
  Zap, 
  Globe, 
  Bell, 
  Cpu, 
  X, 
  Sliders, 
  AlertOctagon, 
  Clock, 
  Server, 
  CheckCircle2, 
  Layers, 
  ChevronRight, 
  Filter, 
  RefreshCw 
} from "lucide-react";
import { Doughnut, Bar, Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title,
} from "chart.js";
import { monitoringService, authService, adminService } from "../services/api";
import AlertDrawer from "../components/AlertDrawer";
import StopCaptureModal from "../components/StopCaptureModal";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  Title
);

const Dashboard = () => {
  const currentUser = authService.getUser();
  const roleName = currentUser?.role?.name || "Security Analyst";
  const isAdmin = roleName === "Security Admin";

  const [status, setStatus] = useState({ is_running: false, is_emulated: false, interface: "", start_time: null });
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  
  // Connection UX
  const [connectionState, setConnectionState] = useState("OFFLINE"); // LIVE, RECONNECTING, OFFLINE
  const [flows, setFlows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState({
    packet_queue_size: 0,
    dropped_packets: 0,
    flows_processed: 0,
    dropped_flows: 0,
    flow_queue_size: 0,
    threats_detected: 0,
    average_inference_latency_ms: 0,
    last_inference_latency_ms: 0
  });

  // Risk filter state
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [selectedFlow, setSelectedFlow] = useState(null);
  const [isStopModalOpen, setIsStopModalOpen] = useState(false);

  // Admin Config controls
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [selectedProfile, setSelectedProfile] = useState("cicids2017");
  const [flowTimeout, setFlowTimeout] = useState(5.0);

  // Timeline controls
  const [timelineMetric, setTimelineMetric] = useState("Flows"); // Flows, Threats
  const [throughputData, setThroughputData] = useState([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const [threatData, setThreatData] = useState([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

  // Admin State
  const [usersList, setUsersList] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);

  // In-app toasts state
  const [toasts, setToasts] = useState([]);

  // WebSockets / Buffering Refs
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const bufferedEventsRef = useRef([]);

  // Uptime counter
  const [uptimeSeconds, setUptimeSeconds] = useState(0);

  useEffect(() => {
    let interval;
    if (status.is_running) {
      interval = setInterval(() => {
        setUptimeSeconds((prev) => prev + 1);
      }, 1000);
    } else {
      setUptimeSeconds(0);
    }
    return () => clearInterval(interval);
  }, [status.is_running]);

  const formatUptime = (secs) => {
    const h = Math.floor(secs / 3600).toString().padStart(2, "0");
    const m = Math.floor((secs % 3600) / 60).toString().padStart(2, "0");
    const s = (secs % 60).toString().padStart(2, "0");
    return `${h}:${m}:${s}`;
  };

  const fetchInterfaces = async () => {
    try {
      const list = await monitoringService.getInterfaces();
      setInterfaces(list);
      if (list.length > 0) {
        setSelectedInterface(list[0]);
      }
    } catch (err) {
      console.error("Failed to load interfaces:", err);
    }
  };

  const fetchHistory = async () => {
    try {
      const flowData = await monitoringService.getFlows({ limit: 40 });
      setFlows(flowData);
      const summaryData = await monitoringService.getTrafficSummary();
      setSummary(summaryData);
    } catch (err) {
      console.error("Failed to load history metrics:", err);
    }
  };

  const fetchAdminData = async () => {
    try {
      const users = await adminService.getUsers(0, 10);
      setUsersList(users);
      const logs = await adminService.getAuditLogs(0, 5);
      setAuditLogs(logs);
    } catch (err) {
      console.error("Failed to fetch admin metadata:", err);
    }
  };

  // WebSocket lifecycle
  const connectWebSocket = () => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      const oldWs = wsRef.current;
      wsRef.current = null;
      oldWs.onclose = null;
      oldWs.onerror = null;
      try {
        oldWs.close();
      } catch (e) {}
    }

    setConnectionState("RECONNECTING");

    const token = localStorage.getItem("token");
    if (!token) {
      setConnectionState("OFFLINE");
      return;
    }

    const wsUrl = `ws://localhost:8000/api/v1/monitoring/ws?token=${token}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      if (wsRef.current === ws) {
        setConnectionState("LIVE");
      }
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        bufferedEventsRef.current.push(msg);
      } catch (err) {
        console.error("Error reading WebSocket msg frame:", err);
      }
    };

    ws.onclose = () => {
      if (wsRef.current === ws) {
        setConnectionState("OFFLINE");
        reconnectTimeoutRef.current = setTimeout(connectWebSocket, 5000);
      }
    };

    ws.onerror = () => {
      if (wsRef.current === ws) {
        try {
          ws.close();
        } catch (e) {}
      }
    };
  };

  const showToast = (alert) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [{ id, alert }, ...prev]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 7000);
  };

  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await fetchInterfaces();
      await fetchHistory();
      
      const statusData = await monitoringService.getSnifferStatus();
      setStatus(statusData);
      setMetrics(statusData);
      if (statusData.interface) {
        setSelectedInterface(statusData.interface);
      }

      if (isAdmin) {
        await fetchAdminData();
      }
      setLoading(false);
      connectWebSocket();
    };

    init();

    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, [isAdmin]);

  // 800ms throttled batch processing
  useEffect(() => {
    const processBatch = () => {
      if (bufferedEventsRef.current.length === 0) return;

      const events = [...bufferedEventsRef.current];
      bufferedEventsRef.current = [];

      // 1. Process flows
      const newFlows = events.filter((e) => e.event_type === "flow.processed").map((e) => e.payload);
      if (newFlows.length > 0) {
        setFlows((prev) => {
          let updated = [...prev];
          for (const flow of newFlows) {
            if (!updated.some((f) => f.id === flow.id)) {
              updated = [flow, ...updated];
            }
          }
          return updated.slice(0, 40);
        });
      }

      // 2. Process alert toasts
      const newAlerts = events.filter((e) => e.event_type === "alert.created" || e.event_type === "alert.updated");
      for (const alertEvt of newAlerts) {
        const alert = alertEvt.payload;
        if (alertEvt.event_type === "alert.created" && (alert.priority === "P1" || alert.risk_level === "Critical")) {
          showToast(alert);
        }
      }

      // 3. Process status & metrics updates
      const latestStatus = events.filter((e) => e.event_type === "monitoring.status").map((e) => e.payload).pop();
      if (latestStatus) {
        setStatus(latestStatus);
        setMetrics(latestStatus);
      } else {
        const processedCount = newFlows.length;
        const threatCount = events.filter((e) => e.event_type === "alert.created").length;
        if (processedCount > 0 || threatCount > 0) {
          setMetrics((prev) => ({
            ...prev,
            flows_processed: prev.flows_processed + processedCount,
            threats_detected: prev.threats_detected + threatCount
          }));
        }
      }

      // 4. Update timeline trends
      const tickFlowCount = newFlows.length;
      const tickThreatCount = newFlows.filter((f) => f.is_attack || f.anomaly_detected).length;
      setThroughputData((history) => [...history.slice(1), tickFlowCount]);
      setThreatData((history) => [...history.slice(1), tickThreatCount]);
    };

    const interval = setInterval(processBatch, 800);
    return () => clearInterval(interval);
  }, []);

  const handleToggleSniffer = async () => {
    try {
      if (status.is_running) {
        setIsStopModalOpen(true);
      } else {
        await monitoringService.startSniffer(selectedInterface);
        const statusData = await monitoringService.getSnifferStatus();
        setStatus(statusData);
        setMetrics(statusData);
      }
    } catch (err) {
      console.error("Failed to start packet capture:", err);
    }
  };

  const confirmStopSniffer = async () => {
    try {
      await monitoringService.stopSniffer();
      const statusData = await monitoringService.getSnifferStatus();
      setStatus(statusData);
      setMetrics(statusData);
    } catch (err) {
      console.error("Failed to stop packet capture:", err);
    }
  };

  // Memoized Filtered flows for the Live Threat Feed
  const filteredFlows = useMemo(() => {
    return flows.filter((f) => {
      if (riskFilter === "ALL") return true;
      return f.risk_level?.toUpperCase() === riskFilter;
    });
  }, [flows, riskFilter]);

  // Memoized Risk Distribution breakdown
  const riskCounts = useMemo(() => {
    return {
      CRITICAL: flows.filter((f) => f.risk_level === "Critical").length,
      HIGH: flows.filter((f) => f.risk_level === "High").length,
      MEDIUM: flows.filter((f) => f.risk_level === "Medium").length,
      LOW: flows.filter((f) => f.risk_level === "Low" || !f.risk_level).length,
    };
  }, [flows]);

  const totalRiskEvents = flows.length || 1;

  const getRiskBadge = (risk) => {
    switch (risk?.toLowerCase()) {
      case "critical":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "high":
        return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "medium":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      default:
        return "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
    }
  };

  const getPriorityBadge = (prio) => {
    switch (prio) {
      case "P1":
        return "bg-red-600 text-white font-bold";
      case "P2":
        return "bg-amber-600 text-white font-bold";
      case "P3":
        return "bg-indigo-600 text-white font-semibold";
      default:
        return "bg-slate-700 text-slate-300";
    }
  };

  // Memoized Chart.js options
  const chartOptions = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#0f172a",
        titleColor: "#94a3b8",
        bodyColor: "#f8fafc",
        borderColor: "#334155",
        borderWidth: 1,
      },
    },
    scales: {
      x: { grid: { display: false }, ticks: { color: "#64748b", font: { size: 10 } } },
      y: { grid: { color: "rgba(51, 65, 85, 0.3)" }, ticks: { color: "#64748b", font: { size: 10 } } },
    },
  }), []);

  // Memoized Chart.js data
  const chartData = useMemo(() => ({
    labels: ["12s ago", "11s ago", "10s ago", "9s ago", "8s ago", "7s ago", "6s ago", "5s ago", "4s ago", "3s ago", "2s ago", "Now"],
    datasets: [
      {
        label: timelineMetric === "Flows" ? "Processed Flows" : "Active Threats",
        data: timelineMetric === "Flows" ? throughputData : threatData,
        borderColor: timelineMetric === "Flows" ? "#6366f1" : "#f43f5e",
        backgroundColor: timelineMetric === "Flows" ? "rgba(99, 102, 241, 0.15)" : "rgba(244, 63, 94, 0.15)",
        fill: true,
        tension: 0.3,
        pointRadius: 2,
      },
    ],
  }), [timelineMetric, throughputData, threatData]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-indigo-500"></div>
        <p className="text-xs text-slate-500 font-medium font-mono animate-pulse">Initializing Security Operations Center...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">

      {/* Real-time In-App Toasts Container */}
      <div className="fixed top-20 right-8 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            onClick={() => setSelectedFlow(t.alert)}
            className="pointer-events-auto bg-slate-900 border-l-4 border-l-rose-500 border border-slate-800 p-4 rounded-xl shadow-2xl animate-in slide-in-from-right duration-300 flex items-start justify-between cursor-pointer hover:bg-slate-800/90"
          >
            <div>
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span className="text-xs font-bold text-slate-100 uppercase tracking-wider">P1 CRITICAL THREAT</span>
              </div>
              <p className="text-xs font-semibold text-rose-300 mt-1">{t.alert.attack_type || "Malicious Intrusion Detected"}</p>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">Src: {t.alert.source_ip || t.alert.src_ip} • Score: {(t.alert.threat_score || 90).toFixed(1)}</p>
            </div>
            <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-1 rounded">View →</span>
          </div>
        ))}
      </div>

      {/* Section 1: Live Monitoring Status Bar */}
      <div className="bg-slate-900/60 p-5 rounded-2xl border border-slate-800 backdrop-blur-md flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-4">
          
          {/* Status Badge */}
          <div className="flex items-center gap-2">
            {status.is_running ? (
              status.is_emulated ? (
                <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
                  ● TRAFFIC EMULATOR
                </span>
              ) : (
                <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  ● LIVE CAPTURE
                </span>
              )
            ) : (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs font-bold bg-slate-800 text-slate-400 border border-slate-700">
                ● MONITORING OFFLINE
              </span>
            )}
          </div>

          {/* Environmental Metadata */}
          <div className="flex items-center gap-4 text-xs font-mono text-slate-300">
            <div className="flex items-center gap-1.5">
              <Radio className="w-4 h-4 text-indigo-400" />
              <span>Interface: <strong className="text-slate-100">{status.interface || selectedInterface || "Wi-Fi"}</strong></span>
            </div>
            <div className="flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-purple-400" />
              <span>Profile: <strong className="text-purple-300 uppercase">{status.model_profile || "CICIDS2017"}</strong></span>
            </div>
            <div className="flex items-center gap-1.5">
              <Clock className="w-4 h-4 text-emerald-400" />
              <span>Uptime: <strong className="text-emerald-300">{formatUptime(uptimeSeconds)}</strong></span>
            </div>
          </div>

        </div>

        {/* WebSocket Connection UX State */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-xs font-mono">
            {connectionState === "LIVE" ? (
              <span className="text-emerald-400 flex items-center gap-1 font-semibold">
                <Wifi className="w-4 h-4" /> Live Socket Linked
              </span>
            ) : connectionState === "RECONNECTING" ? (
              <span className="text-amber-400 flex items-center gap-1 animate-pulse font-semibold">
                <RefreshCw className="w-4 h-4 animate-spin" /> Reconnecting WS...
              </span>
            ) : (
              <span className="text-rose-400 flex items-center gap-1 font-semibold">
                <WifiOff className="w-4 h-4" /> WS Disconnected
              </span>
            )}
          </div>

          {/* Quick Capture Control for Admins */}
          {isAdmin && (
            <button
              onClick={handleToggleSniffer}
              className={`px-3 py-1.5 rounded-xl text-xs font-bold transition flex items-center gap-1.5 ${
                status.is_running
                  ? "bg-rose-600/20 text-rose-300 border border-rose-500/30 hover:bg-rose-600/30"
                  : "bg-emerald-600 hover:bg-emerald-500 text-white shadow-md shadow-emerald-600/20"
              }`}
            >
              {status.is_running ? <Square className="w-3 h-3 fill-current" /> : <Play className="w-3 h-3 fill-current" />}
              {status.is_running ? "Stop Monitoring" : "Start Monitoring"}
            </button>
          )}
        </div>
      </div>

      {/* Section 2: Separated Network Activity vs Security Intelligence KPIs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Network Activity Metrics */}
        <div className="bg-slate-900/50 p-5 rounded-2xl border border-slate-800 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Activity className="w-4 h-4 text-indigo-400" /> Network Activity & Ingress Rates
          </h3>
          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-[10px] font-semibold uppercase text-slate-500 block">Total Flows</span>
              <span className="text-xl font-bold text-slate-100 font-mono mt-1 block">
                {(metrics.flows_processed || 0).toLocaleString()}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">Aggregated</span>
            </div>
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-[10px] font-semibold uppercase text-slate-500 block">Packets Captured</span>
              <span className="text-xl font-bold text-indigo-400 font-mono mt-1 block">
                {(status.packets_captured || 0).toLocaleString()}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">Socket Ingress</span>
            </div>
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-[10px] font-semibold uppercase text-slate-500 block">Ingress Queue Load</span>
              <span className="text-xl font-bold text-cyan-400 font-mono mt-1 block">
                {metrics.packet_queue_size || 0} / 1000
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">Bounded Capacity</span>
            </div>
          </div>
        </div>

        {/* Security Intelligence Metrics */}
        <div className="bg-slate-900/50 p-5 rounded-2xl border border-slate-800 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" /> Security Intelligence & Threat Detection
          </h3>
          <div className="grid grid-cols-3 gap-3 text-center">
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-[10px] font-semibold uppercase text-slate-500 block">Active Threats</span>
              <span className="text-xl font-bold text-rose-400 font-mono mt-1 block">
                {metrics.threats_detected || 0}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">Phase 5 Triggers</span>
            </div>
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-[10px] font-semibold uppercase text-slate-500 block">Critical P1 Alerts</span>
              <span className="text-xl font-bold text-amber-400 font-mono mt-1 block">
                {flows.filter((f) => f.priority === "P1" || f.risk_level === "Critical").length}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">Require Triage</span>
            </div>
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-[10px] font-semibold uppercase text-slate-500 block">Open Incidents</span>
              <span className="text-xl font-bold text-purple-400 font-mono mt-1 block">
                {flows.filter((f) => f.incident_id).length}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">Correlated Clusters</span>
            </div>
          </div>
        </div>

      </div>

      {/* Section 3: Threat Activity Timeline & Risk Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Threat Activity Timeline Chart */}
        <div className="lg:col-span-2 bg-slate-900/50 p-5 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-100">Threat Activity Timeline</h3>
              <p className="text-xs text-slate-400">Real-time throughput metrics aggregated across 300ms socket intervals</p>
            </div>

            <div className="flex items-center gap-2 bg-slate-950/60 p-1 rounded-xl border border-slate-800">
              <button
                onClick={() => setTimelineMetric("Flows")}
                className={`px-3 py-1 rounded-lg text-xs font-medium transition ${
                  timelineMetric === "Flows" ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Flows
              </button>
              <button
                onClick={() => setTimelineMetric("Threats")}
                className={`px-3 py-1 rounded-lg text-xs font-medium transition ${
                  timelineMetric === "Threats" ? "bg-rose-600 text-white" : "text-slate-400 hover:text-slate-200"
                }`}
              >
                Threats
              </button>
            </div>
          </div>

          <div className="h-60">
            <Line data={chartData} options={chartOptions} />
          </div>
        </div>

        {/* Risk Distribution Breakdown */}
        <div className="bg-slate-900/50 p-5 rounded-2xl border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-100">Risk Level Distribution</h3>
            <span className="text-xs text-slate-400">Buffered Events</span>
          </div>

          {/* Horizontal Progress Bar Visualization */}
          <div className="space-y-3 pt-2">
            {[
              { label: "Critical", count: riskCounts.CRITICAL, color: "bg-rose-500", key: "CRITICAL" },
              { label: "High", count: riskCounts.HIGH, color: "bg-orange-500", key: "HIGH" },
              { label: "Medium", count: riskCounts.MEDIUM, color: "bg-amber-500", key: "MEDIUM" },
              { label: "Low", count: riskCounts.LOW, color: "bg-emerald-500", key: "LOW" },
            ].map((r) => {
              const pct = Math.round((r.count / totalRiskEvents) * 100);
              const isSelected = riskFilter === r.key;
              return (
                <div
                  key={r.label}
                  onClick={() => setRiskFilter(isSelected ? "ALL" : r.key)}
                  className={`p-3 rounded-xl border cursor-pointer transition ${
                    isSelected ? "bg-slate-800 border-indigo-500" : "bg-slate-950/40 border-slate-800 hover:bg-slate-800/50"
                  }`}
                >
                  <div className="flex justify-between text-xs mb-1.5 font-medium">
                    <span className="text-slate-200">{r.label} Risk</span>
                    <span className="text-slate-400 font-mono">{r.count} ({pct}%)</span>
                  </div>
                  <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div className={`h-full ${r.color}`} style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>

          {riskFilter !== "ALL" && (
            <button
              onClick={() => setRiskFilter("ALL")}
              className="w-full text-center text-xs text-indigo-400 hover:underline pt-2"
            >
              Clear Risk Filter ({riskFilter})
            </button>
          )}
        </div>

      </div>

      {/* Section 4: Live Threat Feed Table */}
      <div className="bg-slate-900/50 rounded-2xl border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <h3 className="text-sm font-bold text-slate-100">Live Threat Feed</h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
              Showing {filteredFlows.length} recent events
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Filter Risk:</span>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((rk) => (
              <button
                key={rk}
                onClick={() => setRiskFilter(rk)}
                className={`px-2.5 py-1 rounded-lg font-medium text-[11px] transition ${
                  riskFilter === rk ? "bg-indigo-600 text-white" : "bg-slate-800/80 text-slate-400 hover:text-slate-200"
                }`}
              >
                {rk}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          {filteredFlows.length === 0 ? (
            <div className="p-12 text-center text-slate-400 text-xs">
              ✓ No threat flows match current risk filter criteria. Monitoring is running active.
            </div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-4">Time</th>
                  <th className="py-3.5 px-4">Source 5-Tuple</th>
                  <th className="py-3.5 px-4">Destination 5-Tuple</th>
                  <th className="py-3.5 px-4">Proto</th>
                  <th className="py-3.5 px-4">Detection</th>
                  <th className="py-3.5 px-4">Threat Score</th>
                  <th className="py-3.5 px-4">Risk</th>
                  <th className="py-3.5 px-4">Priority</th>
                  <th className="py-3.5 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {filteredFlows.map((f, idx) => (
                  <tr
                    key={f.id || f.event_id || idx}
                    onClick={() => setSelectedFlow(f)}
                    className="cursor-pointer transition hover:bg-slate-800/50"
                  >
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                      {new Date(f.captured_at || f.created_at || Date.now()).toLocaleTimeString()}
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-200">
                      {f.source_ip || f.src_ip}:{f.source_port || f.sport}
                    </td>

                    <td className="py-3 px-4 font-mono text-indigo-300">
                      {f.destination_ip || f.dst_ip}:{f.destination_port || f.dsport}
                    </td>

                    <td className="py-3 px-4 font-mono text-purple-400">{f.protocol || "TCP"}</td>

                    <td className="py-3 px-4">
                      <span className="font-semibold text-slate-100">
                        {f.attack_type || f.classification_name || (f.is_attack ? "Intrusion" : "Normal")}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono font-bold text-rose-400">
                      {f.threat_score !== undefined ? f.threat_score.toFixed(1) : "0.0"}
                    </td>

                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getRiskBadge(f.risk_level)}`}>
                        {f.risk_level || "Low"}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${getPriorityBadge(f.priority || "P3")}`}>
                        {f.priority || "P3"}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button className="p-1 rounded bg-slate-800 text-slate-300 hover:text-white">
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Section 5: Security Admin System Health & Config Controls (Admin Only) */}
      {isAdmin && (
        <div className="bg-slate-900/60 p-6 rounded-2xl border border-slate-800 space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <Server className="w-5 h-5 text-indigo-400" /> Platform Infrastructure & Engine Diagnostics
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">Authoritative status of detection workers, queues, and PostgreSQL storage.</p>
            </div>
            <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Admin Privilege
            </span>
          </div>

          {/* System Health Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-slate-400 block text-[10px] uppercase font-semibold">Packet Capture</span>
              <span className={`font-bold mt-1 inline-flex items-center gap-1 ${status.is_running ? "text-emerald-400" : "text-slate-400"}`}>
                <CheckCircle2 className="w-3.5 h-3.5" /> {status.is_running ? "Running" : "Stopped"}
              </span>
            </div>

            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-slate-400 block text-[10px] uppercase font-semibold">Flow Aggregator</span>
              <span className="font-bold text-emerald-400 mt-1 inline-flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Healthy
              </span>
            </div>

            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-slate-400 block text-[10px] uppercase font-semibold">ML Inference</span>
              <span className="font-bold text-emerald-400 mt-1 inline-flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Active (Phase 5)
              </span>
            </div>

            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-slate-400 block text-[10px] uppercase font-semibold">PostgreSQL DB</span>
              <span className="font-bold text-emerald-400 mt-1 inline-flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Connected
              </span>
            </div>

            <div className="bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
              <span className="text-slate-400 block text-[10px] uppercase font-semibold">WebSocket Bus</span>
              <span className={`font-bold mt-1 inline-flex items-center gap-1 ${connectionState === "LIVE" ? "text-emerald-400" : "text-rose-400"}`}>
                <CheckCircle2 className="w-3.5 h-3.5" /> {connectionState}
              </span>
            </div>
          </div>

          {/* Performance & Queue Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono bg-slate-950/40 p-4 rounded-xl border border-slate-800">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Processing Latency (Avg)</span>
              <span className="text-indigo-400 font-bold text-sm">{(metrics.average_inference_latency_ms || 0).toFixed(2)} ms</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Packet Queue Drop Count</span>
              <span className="text-slate-300 font-bold text-sm">{metrics.dropped_packets || 0} Packets</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Flow Queue Drop Count</span>
              <span className="text-slate-300 font-bold text-sm">{metrics.dropped_flows || 0} Flows</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Active Model Profile</span>
              <span className="text-purple-400 font-bold text-sm uppercase">{status.model_profile || "cicids2017"}</span>
            </div>
          </div>

          {/* Capture Controls Settings Form */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Network Interface</label>
              <select
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                disabled={status.is_running}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 disabled:opacity-50"
              >
                {interfaces.map((iface) => (
                  <option key={iface} value={iface}>{iface}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Detection Model Profile</label>
              <select
                value={selectedProfile}
                onChange={(e) => setSelectedProfile(e.target.value)}
                disabled={status.is_running}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 disabled:opacity-50"
              >
                <option value="cicids2017">CICIDS2017 Model Profile (77 Features)</option>
                <option value="unsw_nb15">UNSW-NB15 Model Profile (43 Features)</option>
              </select>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Flow Idle Timeout (Seconds)</label>
              <input
                type="number"
                step="0.5"
                value={flowTimeout}
                onChange={(e) => setFlowTimeout(parseFloat(e.target.value))}
                disabled={status.is_running}
                className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500 disabled:opacity-50"
              />
            </div>
          </div>
        </div>
      )}

      {/* Investigation Drawer Modal */}
      <AlertDrawer
        isOpen={Boolean(selectedFlow)}
        onClose={() => setSelectedFlow(null)}
        flow={selectedFlow}
      />

      {/* Stop Capture Confirmation Modal */}
      <StopCaptureModal
        isOpen={isStopModalOpen}
        onClose={() => setIsStopModalOpen(false)}
        onConfirm={confirmStopSniffer}
      />

    </div>
  );
};

export default Dashboard;
