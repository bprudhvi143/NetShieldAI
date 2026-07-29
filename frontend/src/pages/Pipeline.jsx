import React, { useState, useEffect } from "react";
import { 
  GitCommit, 
  Radio, 
  Cpu, 
  Layers, 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  CheckCircle2, 
  Zap, 
  Database,
  ArrowRight,
  RefreshCw,
  Sliders,
  Server,
  AlertTriangle
} from "lucide-react";
import { monitoringService } from "../services/api";

const Pipeline = () => {
  const [status, setStatus] = useState({ is_running: false, is_emulated: false, interface: "" });
  const [loading, setLoading] = useState(true);

  const fetchStatus = async () => {
    try {
      setLoading(true);
      const data = await monitoringService.getSnifferStatus();
      setStatus(data);
    } catch (err) {
      console.error("Failed to fetch pipeline status:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const stages = [
    {
      id: "ingress",
      title: "1. Network Ingress",
      sub: "Physical Interface Sockets",
      icon: Radio,
      color: "border-indigo-500/40 bg-indigo-950/20 text-indigo-400",
      metrics: [
        { label: "Capture Mode", val: status.is_running ? (status.is_emulated ? "Traffic Emulator" : "Live Socket") : "Stopped" },
        { label: "Interface", val: status.interface || "Default" }
      ]
    },
    {
      id: "capture",
      title: "2. Packet Sniffer Engine",
      sub: "Scapy Bounded Buffer",
      icon: Activity,
      color: "border-blue-500/40 bg-blue-950/20 text-blue-400",
      metrics: [
        { label: "Packets Captured", val: (status.packets_captured || 0).toLocaleString() },
        { label: "Queue Load", val: `${status.packet_queue_size || 0} / 1000` }
      ]
    },
    {
      id: "aggregation",
      title: "3. Flow Aggregation",
      sub: "5-Tuple Stateful Grouping",
      icon: Layers,
      color: "border-purple-500/40 bg-purple-950/20 text-purple-400",
      metrics: [
        { label: "Flows Aggregated", val: (status.flows_processed || 0).toLocaleString() },
        { label: "Idle Timeout", val: `${status.flow_timeout_sec || 5.0}s` }
      ]
    },
    {
      id: "adapter",
      title: "4. Feature Adapter",
      sub: "StandardScaler & OneHotEncoder",
      icon: Sliders,
      color: "border-cyan-500/40 bg-cyan-950/20 text-cyan-400",
      metrics: [
        { label: "Active Profile", val: (status.model_profile || "CICIDS2017").toUpperCase() },
        { label: "Input Features", val: status.model_profile === "unsw_nb15" ? "43 Features" : "77 Features" }
      ]
    },
    {
      id: "isolation_forest",
      title: "5. Isolation Forest",
      sub: "Phase 2 Anomaly Detection",
      icon: Cpu,
      color: "border-amber-500/40 bg-amber-950/20 text-amber-400",
      metrics: [
        { label: "Anomaly Score", val: "Statistical Outlier" },
        { label: "Model Type", val: "Unsupervised iForest" }
      ]
    },
    {
      id: "xgboost_binary",
      title: "6. XGBoost Binary Predictor",
      sub: "Phase 3 Intrusion Classification",
      icon: ShieldCheck,
      color: "border-emerald-500/40 bg-emerald-950/20 text-emerald-400",
      metrics: [
        { label: "Intrusion Signal", val: "Binary Malicious Flag" },
        { label: "Model Type", val: "Gradient Boosted Trees" }
      ]
    },
    {
      id: "xgboost_multiclass",
      title: "7. XGBoost Attack Classifier",
      sub: "Phase 3 Attack Taxonomy",
      icon: Zap,
      color: "border-rose-500/40 bg-rose-950/20 text-rose-400",
      metrics: [
        { label: "Categories", val: "DoS, PortScan, BruteForce" },
        { label: "Condition", val: "Triggered on Intrusion" }
      ]
    },
    {
      id: "risk_scoring",
      title: "8. Risk Scoring Engine",
      sub: "Phase 4 Multi-Vector Scoring",
      icon: Activity,
      color: "border-purple-500/40 bg-purple-950/20 text-purple-400",
      metrics: [
        { label: "Score Range", val: "0.0 - 100.0" },
        { label: "Levels", val: "Critical, High, Med, Low" }
      ]
    },
    {
      id: "alerts",
      title: "9. Alert Management Engine",
      sub: "Phase 6 Deduplication Policy",
      icon: ShieldAlert,
      color: "border-red-500/40 bg-red-950/20 text-red-400",
      metrics: [
        { label: "Threats Triggered", val: (status.threats_detected || 0).toLocaleString() },
        { label: "Deduplication Window", val: "300 Seconds" }
      ]
    },
    {
      id: "incidents",
      title: "10. Incident Management",
      sub: "Phase 6 Correlation & Triage",
      icon: Server,
      color: "border-indigo-500/40 bg-indigo-950/20 text-indigo-400",
      metrics: [
        { label: "Persistence", val: "PostgreSQL & MongoDB" },
        { label: "Broadcast", val: "Real-Time WebSockets" }
      ]
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-md">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-slate-100">End-to-End Threat Detection Pipeline</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Phase 5 Architecture
            </span>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Visual execution path from raw physical network packet capture to AI inference, risk scoring, and incident triage.
          </p>
        </div>

        <button
          onClick={fetchStatus}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-sm font-medium transition shrink-0"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-indigo-400" : ""}`} />
          Refresh Pipeline Status
        </button>
      </div>

      {/* Pipeline Status Summary Banner */}
      <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full ${status.is_running ? "bg-emerald-500 animate-pulse" : "bg-rose-500"}`} />
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Pipeline State</span>
            <span className="text-sm font-bold text-slate-100">
              {status.is_running ? "ACTIVE INFERENCE PIPELINE RUNNING" : "PIPELINE IDLE / STOPPED"}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-6 text-xs text-slate-300 font-mono">
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Avg Latency</span>
            <span className="text-indigo-400 font-bold">{(status.average_inference_latency_ms || 0).toFixed(2)} ms</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Flows Processed</span>
            <span className="text-emerald-400 font-bold">{(status.flows_processed || 0).toLocaleString()}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[10px] uppercase">Threats Detected</span>
            <span className="text-rose-400 font-bold">{(status.threats_detected || 0).toLocaleString()}</span>
          </div>
        </div>
      </div>

      {/* Stage Grid Flow */}
      <div className="space-y-4">
        {stages.map((st, idx) => (
          <div key={st.id} className="relative">
            <div className={`p-5 rounded-2xl border ${st.color} flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition duration-200 hover:scale-[1.005]`}>
              
              {/* Left: Icon & Stage Name */}
              <div className="flex items-center gap-4">
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 shrink-0">
                  <st.icon className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-100">{st.title}</h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">{st.sub}</p>
                </div>
              </div>

              {/* Right: Metrics Badges */}
              <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
                {st.metrics.map((m, mIdx) => (
                  <div key={mIdx} className="bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 text-[10px] uppercase block">{m.label}</span>
                    <span className="font-semibold text-slate-200">{m.val}</span>
                  </div>
                ))}
                <div className="flex items-center gap-1 text-emerald-400 text-xs font-semibold px-2.5 py-1 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Stage Verified</span>
                </div>
              </div>

            </div>

            {/* Connecting Arrow */}
            {idx < stages.length - 1 && (
              <div className="flex justify-center my-1.5">
                <div className="w-0.5 h-4 bg-slate-800 flex items-center justify-center">
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500 rotate-90" />
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default Pipeline;
