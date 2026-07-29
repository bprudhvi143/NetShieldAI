import React from "react";
import { 
  X, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Clock, 
  Activity, 
  FileText, 
  Layers, 
  User, 
  ExternalLink,
  Info,
  Zap,
  HelpCircle
} from "lucide-react";
import { useNavigate } from "react-router-dom";

const AlertDrawer = ({ isOpen, onClose, alert, flow }) => {
  const navigate = useNavigate();

  if (!isOpen || (!alert && !flow)) return null;

  // Standardize data from either alert object or flow object
  const data = alert || flow;
  
  const id = data.id || data.event_id || "EVT-UNKNOWN";
  const timestamp = data.created_at || data.captured_at || new Date().toISOString();
  const sourceIp = data.source_ip || data.src_ip || "N/A";
  const sourcePort = data.source_port || data.sport || "N/A";
  const destIp = data.destination_ip || data.dst_ip || "N/A";
  const destPort = data.destination_port || data.dsport || "N/A";
  const protocol = data.protocol || "TCP";
  const attackType = data.attack_type || data.classification_name || (data.is_attack ? "Malicious Intrusion" : "Normal Traffic");
  const threatScore = data.threat_score !== undefined ? data.threat_score.toFixed(1) : "0.0";
  const riskLevel = data.risk_level || "Low";
  const priority = data.priority || "P3";
  const anomalyScore = data.anomaly_score !== undefined ? data.anomaly_score.toFixed(4) : "0.0000";
  const attackProb = data.attack_probability !== undefined ? (data.attack_probability * 100).toFixed(1) + "%" : "0.0%";
  const signalStatus = data.signal_status || (data.anomaly_detected && data.is_attack ? "CONFIRMED_THREAT" : data.is_attack ? "INTRUSION_ONLY" : data.anomaly_detected ? "ANOMALY_ONLY" : "NORMAL");
  const incidentId = data.incident_id || null;
  const repeatCount = data.repeat_count || 1;
  const latencyMs = data.processing_latency_ms ? `${data.processing_latency_ms.toFixed(2)} ms` : "N/A";

  const getRiskBadgeColor = (risk) => {
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

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-sm flex justify-end transition-opacity duration-300">
      <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl overflow-hidden animate-in slide-in-from-right duration-300">
        
        {/* Drawer Header */}
        <div className="p-6 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl border ${getRiskBadgeColor(riskLevel)}`}>
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-slate-100">Threat Investigation</h3>
                <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider ${getPriorityBadge(priority)}`}>
                  {priority}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">ID: {id} • Captured {new Date(timestamp).toLocaleString()}</p>
            </div>
          </div>

          <button 
            onClick={onClose}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Drawer Body - Scrollable */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-4 gap-3 bg-slate-950/50 p-4 rounded-xl border border-slate-800/80 text-center">
            <div>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">Threat Score</span>
              <span className="text-xl font-bold text-rose-400 font-mono">{threatScore}</span>
            </div>
            <div>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">Risk Level</span>
              <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded inline-block mt-1 border ${getRiskBadgeColor(riskLevel)}`}>
                {riskLevel}
              </span>
            </div>
            <div>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">Attack Prob</span>
              <span className="text-base font-bold text-purple-400 font-mono mt-0.5 block">{attackProb}</span>
            </div>
            <div>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">Signal Status</span>
              <span className="text-[11px] font-semibold text-slate-300 font-mono block mt-1 truncate" title={signalStatus}>
                {signalStatus}
              </span>
            </div>
          </div>

          {/* "Why Was This Threat Detected?" Section */}
          <div className="bg-slate-950/60 p-5 rounded-xl border border-slate-800/80 space-y-3">
            <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <HelpCircle className="w-4 h-4 text-indigo-400" />
              Why Was This Threat Detected?
            </h4>
            <div className="space-y-2 text-xs">
              <div className="flex items-start gap-2 text-slate-300">
                <CheckCircle2 className={`w-4 h-4 mt-0.5 shrink-0 ${data.anomaly_detected ? "text-amber-400" : "text-slate-600"}`} />
                <div>
                  <span className="font-semibold text-slate-100">Anomaly Detection Status:</span>{" "}
                  {data.anomaly_detected ? (
                    <span className="text-amber-300">Isolation Forest identified statistical outlier deviation (Anomaly Score: {anomalyScore})</span>
                  ) : (
                    <span className="text-slate-400">Within expected baseline threshold</span>
                  )}
                </div>
              </div>

              <div className="flex items-start gap-2 text-slate-300">
                <CheckCircle2 className={`w-4 h-4 mt-0.5 shrink-0 ${data.is_attack ? "text-rose-400" : "text-slate-600"}`} />
                <div>
                  <span className="font-semibold text-slate-100">Intrusion Classifier Decision:</span>{" "}
                  {data.is_attack ? (
                    <span className="text-rose-300">XGBoost model confirmed intrusion signature ({attackProb} malicious confidence)</span>
                  ) : (
                    <span className="text-slate-400">Classified as normal network communication</span>
                  )}
                </div>
              </div>

              <div className="flex items-start gap-2 text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" />
                <div>
                  <span className="font-semibold text-slate-100">Classification Category:</span>{" "}
                  <span className="text-indigo-300 font-mono font-semibold">{attackType}</span>
                </div>
              </div>

              <div className="flex items-start gap-2 text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-purple-400 mt-0.5 shrink-0" />
                <div>
                  <span className="font-semibold text-slate-100">Risk Assessment Vector:</span>{" "}
                  <span className="text-purple-300">Composite score evaluated from attack severity, anomaly weight, and network target criticality.</span>
                </div>
              </div>
            </div>
          </div>

          {/* Network 5-Tuple Connection Info */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-indigo-400" />
              Network Connection 5-Tuple
            </h4>
            <div className="grid grid-cols-2 gap-3 text-xs bg-slate-950/40 p-4 rounded-xl border border-slate-800 font-mono">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Source Address</span>
                <span className="text-slate-200 font-semibold text-sm">{sourceIp} : {sourcePort}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Destination Address</span>
                <span className="text-slate-200 font-semibold text-sm">{destIp} : {destPort}</span>
              </div>
              <div className="pt-2 border-t border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Transport Protocol</span>
                <span className="text-indigo-300 font-semibold">{protocol}</span>
              </div>
              <div className="pt-2 border-t border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Inference Latency</span>
                <span className="text-slate-300">{latencyMs}</span>
              </div>
            </div>
          </div>

          {/* Associated Incident Information */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              Incident Correlation
            </h4>
            <div className="bg-slate-950/40 p-4 rounded-xl border border-slate-800 flex items-center justify-between text-xs">
              <div>
                {incidentId ? (
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-100">Associated Incident #{incidentId}</span>
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/20">
                        Correlated Threat
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px] mt-1">Deduplicated occurrences: {repeatCount} event(s)</p>
                  </div>
                ) : (
                  <div>
                    <span className="text-slate-300 font-semibold">No incident associated</span>
                    <p className="text-slate-500 text-[11px] mt-0.5">Alert is standalone or pending incident correlation policy</p>
                  </div>
                )}
              </div>

              {incidentId && (
                <button
                  onClick={() => navigate("/incidents")}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-medium transition"
                >
                  <span>View Incident</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Feature Snapshot JSON Inspection (if available) */}
          {data.feature_snapshot && Object.keys(data.feature_snapshot).length > 0 && (
            <div className="space-y-3">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <FileText className="w-4 h-4 text-slate-400" />
                Aggregated Feature Snapshot
              </h4>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 max-h-48 overflow-y-auto text-slate-300 font-mono text-[11px]">
                <pre>{JSON.stringify(data.feature_snapshot, null, 2)}</pre>
              </div>
            </div>
          )}

        </div>

        {/* Drawer Footer Actions */}
        <div className="p-4 bg-slate-950/90 border-t border-slate-800 flex items-center justify-between shrink-0">
          <span className="text-xs text-slate-500">Pipeline Profile: {data.model_version || "CICIDS2017 / Phase 5"}</span>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-xl text-xs font-medium transition"
          >
            Close Inspector
          </button>
        </div>

      </div>
    </div>
  );
};

export default AlertDrawer;
