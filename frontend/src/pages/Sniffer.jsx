import React, { useState, useEffect, useRef } from "react";
import { 
  Play, 
  Square, 
  RefreshCw, 
  ArrowLeft, 
  ArrowRight, 
  Radio, 
  Cpu, 
  Wifi, 
  WifiOff, 
  Database,
  Search,
  Filter,
  Layers,
  ChevronRight,
  ShieldAlert
} from "lucide-react";
import { monitoringService } from "../services/api";
import AlertDrawer from "../components/AlertDrawer";

const Sniffer = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [isEmulated, setIsEmulated] = useState(false);
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  
  // Table Mode: 'LIVE' or 'HISTORY'
  const [tableMode, setTableMode] = useState("LIVE");
  
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const limit = 15;

  // Filter States
  const [filterSrcIp, setFilterSrcIp] = useState("");
  const [filterDstIp, setFilterDstIp] = useState("");
  const [filterProtocol, setFilterProtocol] = useState("");
  const [filterRisk, setFilterRisk] = useState("");
  const [filterPriority, setFilterPriority] = useState("");

  const [selectedFlow, setSelectedFlow] = useState(null);

  const [wsState, setWsState] = useState("OFFLINE");
  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const fetchInterfaces = async () => {
    try {
      const list = await monitoringService.getInterfaces();
      setInterfaces(list);
      if (list.length > 0) {
        setSelectedInterface(list[0]);
      }
    } catch (err) {
      console.error("Failed to fetch network interfaces:", err);
    }
  };

  const fetchStatus = async () => {
    try {
      const statusData = await monitoringService.getSnifferStatus();
      setIsRunning(statusData.is_running);
      setIsEmulated(statusData.is_emulated);
      if (statusData.is_running && statusData.interface) {
        setSelectedInterface(statusData.interface);
      }
    } catch (err) {
      console.error("Failed to fetch sniffer status:", err);
    }
  };

  const fetchFlowsHistory = async (page = 1) => {
    setLoading(true);
    try {
      const skip = (page - 1) * limit;
      const params = {
        skip,
        limit,
        src_ip: filterSrcIp || undefined,
        dst_ip: filterDstIp || undefined,
        protocol: filterProtocol || undefined,
        risk_level: filterRisk || undefined,
        priority: filterPriority || undefined
      };
      const flowData = await monitoringService.getFlows(params);
      setFlows(flowData);
      setTotalCount(flowData.length);
    } catch (err) {
      console.error("Failed to fetch flow logs:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleToggleSniffer = async () => {
    try {
      if (isRunning) {
        await monitoringService.stopSniffer();
        setIsRunning(false);
      } else {
        await monitoringService.startSniffer(selectedInterface);
        setIsRunning(true);
        setCurrentPage(1);
      }
      setTimeout(fetchStatus, 500);
    } catch (err) {
      console.error("Error toggling sniffer session:", err);
    }
  };

  const bufferedFlowsRef = useRef([]);

  // 600ms throttled batch processing for Live Sniffer
  useEffect(() => {
    if (tableMode !== "LIVE") return;

    const interval = setInterval(() => {
      if (bufferedFlowsRef.current.length === 0) return;

      const newBatch = [...bufferedFlowsRef.current];
      bufferedFlowsRef.current = [];

      setFlows((prev) => {
        let updated = [...prev];
        for (const flow of newBatch) {
          if (!updated.some((f) => f.id === flow.id)) {
            updated = [flow, ...updated];
          }
        }
        return updated.slice(0, 40);
      });
    }, 600);

    return () => clearInterval(interval);
  }, [tableMode]);

  // WebSocket connection for LIVE streaming
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

    setWsState("RECONNECTING");

    const token = localStorage.getItem("token");
    if (!token) {
      setWsState("OFFLINE");
      return;
    }

    const wsUrl = `ws://localhost:8000/api/v1/monitoring/ws?token=${token}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      if (wsRef.current === ws) {
        setWsState("LIVE");
      }
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.event_type === "flow.processed") {
          bufferedFlowsRef.current.push(msg.payload);
        }
      } catch (err) {
        console.error("WS message parse error:", err);
      }
    };

    ws.onclose = () => {
      if (wsRef.current === ws) {
        setWsState("OFFLINE");
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

  useEffect(() => {
    fetchInterfaces();
    fetchStatus();

    if (tableMode === "LIVE") {
      connectWebSocket();
    } else {
      if (wsRef.current) wsRef.current.close();
      fetchFlowsHistory(currentPage);
    }

    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    };
  }, [tableMode]);

  useEffect(() => {
    if (tableMode === "HISTORY") {
      fetchFlowsHistory(currentPage);
    }
  }, [currentPage, filterSrcIp, filterDstIp, filterProtocol, filterRisk, filterPriority]);

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

  return (
    <div className="space-y-6">
      {/* Top Header Controls Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-md">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-slate-100">Packet Sniffer & Flow Inspector</h1>
            <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${
              wsState === "LIVE" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-slate-800 text-slate-400"
            }`}>
              {wsState === "LIVE" ? "● STREAMING" : "OFFLINE"}
            </span>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Real-time packet capture, flow feature aggregation, and historical database query inspector.
          </p>
        </div>

        {/* Interface & Start/Stop controls */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 bg-slate-950/60 px-3 py-1.5 rounded-xl border border-slate-800">
            <Radio className="w-4 h-4 text-indigo-400" />
            <select
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isRunning}
              className="bg-transparent text-xs font-medium text-slate-200 focus:outline-none disabled:opacity-50"
            >
              {interfaces.map((iface) => (
                <option key={iface} value={iface} className="bg-slate-900 text-slate-200">
                  {iface}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleToggleSniffer}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition shadow-lg ${
              isRunning
                ? "bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/20"
                : "bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/20"
            }`}
          >
            {isRunning ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" />
                Stop Sniffer
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                Start Sniffer
              </>
            )}
          </button>
        </div>
      </div>

      {/* Mode Switcher & Filter Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/40 p-4 rounded-xl border border-slate-800">
        
        {/* Toggle Mode */}
        <div className="flex items-center gap-2 bg-slate-950/60 p-1 rounded-xl border border-slate-800/80">
          <button
            onClick={() => setTableMode("LIVE")}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold transition ${
              tableMode === "LIVE"
                ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/20"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            Live WebSocket Stream
          </button>

          <button
            onClick={() => setTableMode("HISTORY")}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-semibold transition ${
              tableMode === "HISTORY"
                ? "bg-purple-600 text-white shadow-md shadow-purple-600/20"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Database className="w-3.5 h-3.5" />
            Historical Flow Logs
          </button>
        </div>

        {/* Filters if History mode */}
        {tableMode === "HISTORY" && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <input
              type="text"
              placeholder="Filter Source IP..."
              value={filterSrcIp}
              onChange={(e) => setFilterSrcIp(e.target.value)}
              className="bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 w-36"
            />
            <input
              type="text"
              placeholder="Filter Dst IP..."
              value={filterDstIp}
              onChange={(e) => setFilterDstIp(e.target.value)}
              className="bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 w-36"
            />
            <select
              value={filterRisk}
              onChange={(e) => setFilterRisk(e.target.value)}
              className="bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-purple-500"
            >
              <option value="">All Risks</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        )}
      </div>

      {/* Main Flows Table */}
      <div className="bg-slate-900/50 rounded-xl border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-slate-200">
              {tableMode === "LIVE" ? "Live Processed Flows Feed" : "Historical Database Flow Logs"}
            </h3>
            {tableMode === "LIVE" && isRunning && (
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
            )}
          </div>

          <span className="text-xs text-slate-400">
            {tableMode === "LIVE" ? `Buffered ${flows.length} events` : `Page ${currentPage}`}
          </span>
        </div>

        <div className="overflow-x-auto">
          {loading ? (
            <div className="h-64 flex items-center justify-center">
              <RefreshCw className="w-6 h-6 animate-spin text-indigo-400" />
            </div>
          ) : flows.length === 0 ? (
            <div className="p-12 text-center text-slate-400 text-xs">
              {tableMode === "LIVE" ? "Waiting for live network flows... Ensure sniffer is running." : "No historical flows match current search criteria."}
            </div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3.5 px-4">Time</th>
                  <th className="py-3.5 px-4">5-Tuple Source → Dest</th>
                  <th className="py-3.5 px-4">Proto</th>
                  <th className="py-3.5 px-4">Classification</th>
                  <th className="py-3.5 px-4">Threat Score</th>
                  <th className="py-3.5 px-4">Risk</th>
                  <th className="py-3.5 px-4 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {flows.map((f, idx) => (
                  <tr
                    key={f.id || f.event_id || idx}
                    onClick={() => setSelectedFlow(f)}
                    className="cursor-pointer transition hover:bg-slate-800/50"
                  >
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                      {new Date(f.captured_at || f.created_at || Date.now()).toLocaleTimeString()}
                    </td>

                    <td className="py-3 px-4 font-mono">
                      <span className="text-slate-100">{f.source_ip || f.src_ip}:{f.source_port || f.sport}</span>
                      <span className="text-slate-500 mx-1 border-b border-slate-700">→</span>
                      <span className="text-indigo-300">{f.destination_ip || f.dst_ip}:{f.destination_port || f.dsport}</span>
                    </td>

                    <td className="py-3 px-4 font-mono text-indigo-400">{f.protocol}</td>

                    <td className="py-3 px-4">
                      <span className="font-semibold text-slate-200">
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

        {/* Pagination if History Mode */}
        {tableMode === "HISTORY" && (
          <div className="p-4 border-t border-slate-800 flex items-center justify-between">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 rounded-lg text-xs font-medium"
            >
              Previous Page
            </button>
            <span className="text-xs text-slate-400">Page {currentPage}</span>
            <button
              onClick={() => setCurrentPage((p) => p + 1)}
              disabled={flows.length < limit}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 rounded-lg text-xs font-medium"
            >
              Next Page
            </button>
          </div>
        )}
      </div>

      {/* Detail Inspection Drawer */}
      <AlertDrawer
        isOpen={Boolean(selectedFlow)}
        onClose={() => setSelectedFlow(null)}
        flow={selectedFlow}
      />
    </div>
  );
};

export default Sniffer;
