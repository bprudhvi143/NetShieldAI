import React, { useState, useEffect } from "react";
import { 
  ShieldAlert, 
  RefreshCw, 
  ArrowLeft, 
  ArrowRight, 
  User 
} from "lucide-react";
import { adminService } from "../services/api";

const AuditLogs = () => {
  const [logs, setLogs] = useState([]);
  const [users, setUsers] = useState({});
  const [loading, setLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const limit = 15;

  const fetchUsersAndLogs = async (page) => {
    setLoading(true);
    try {
      const skip = (page - 1) * limit;
      
      // 1. Fetch users registry first to map user ID to emails in logs
      const usersList = await adminService.getUsers(0, 100);
      const userMap = {};
      usersList.forEach(u => {
        userMap[u.id] = u.email;
      });
      setUsers(userMap);

      // 2. Fetch audit logs
      const logData = await adminService.getAuditLogs(skip, limit);
      setLogs(logData);
    } catch (err) {
      console.error("Failed to retrieve system audit logs:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsersAndLogs(currentPage);
  }, [currentPage]);

  const handleNextPage = () => {
    if (logs.length === limit) {
      setCurrentPage(prev => prev + 1);
    }
  };

  const handlePrevPage = () => {
    if (currentPage > 1) {
      setCurrentPage(prev => prev - 1);
    }
  };

  // Helper to format action names into user-friendly badges
  const getActionBadge = (action) => {
    const act = action.toUpperCase();
    if (act.includes("SUCCESS") || act.includes("REGISTERED")) {
      return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    } else if (act.includes("FAILED") || act.includes("ALERT")) {
      return "bg-rose-500/10 text-rose-400 border border-rose-500/20";
    } else if (act.includes("MONITORING")) {
      return "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20";
    } else {
      return "bg-slate-800 text-slate-400 border border-slate-700/80";
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-6 bg-slate-900 border border-slate-800 rounded-2xl">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 flex items-center justify-center">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100">Security Audit Logs</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Review chronological security, login, and background action events.
            </p>
          </div>
        </div>

        <button
          onClick={() => fetchUsersAndLogs(currentPage)}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 text-slate-300 rounded-xl text-sm font-semibold transition flex items-center gap-1.5 justify-center"
        >
          <RefreshCw className="w-4 h-4" /> Reload Logs
        </button>
      </div>

      {/* Logs Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm border-collapse">
            <thead>
              <tr className="bg-slate-950/40 text-slate-400 text-xs font-semibold uppercase tracking-wider border-b border-slate-800">
                <th className="py-4 px-6">Timestamp</th>
                <th className="py-4 px-6">Event Action</th>
                <th className="py-4 px-6">User Accounts</th>
                <th className="py-4 px-6">IP Address</th>
                <th className="py-4 px-6">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {loading && logs.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-8 text-center text-slate-500">
                    Loading security log events...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan="5" className="py-12 text-center text-slate-500">
                    No security audit logs found.
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/10 transition">
                    <td className="py-3.5 px-6 font-mono text-xs text-slate-400">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-6">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${getActionBadge(log.action)}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3.5 px-6 font-mono text-xs">
                      {log.user_id ? (
                        <span className="text-slate-200 font-semibold">{users[log.user_id] || `ID: ${log.user_id}`}</span>
                      ) : (
                        <span className="text-slate-500">Anonymous / System</span>
                      )}
                    </td>
                    <td className="py-3.5 px-6 font-mono text-xs text-slate-400">
                      {log.ip_address || "N/A"}
                    </td>
                    <td className="py-3.5 px-6 text-slate-400 max-w-sm truncate" title={log.details}>
                      {log.details}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pager */}
        <div className="p-4 border-t border-slate-800 flex items-center justify-between">
          <span className="text-xs text-slate-500">
            Page {currentPage} | showing max {limit} logs per page
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={handlePrevPage}
              disabled={currentPage === 1 || loading}
              className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 border border-slate-700 disabled:hover:bg-slate-800 text-slate-300 rounded-lg text-xs font-semibold flex items-center gap-1 transition"
            >
              <ArrowLeft className="w-3.5 h-3.5" /> Previous
            </button>
            <button
              onClick={handleNextPage}
              disabled={logs.length < limit || loading}
              className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 border border-slate-700 disabled:hover:bg-slate-800 text-slate-300 rounded-lg text-xs font-semibold flex items-center gap-1 transition"
            >
              Next <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuditLogs;
