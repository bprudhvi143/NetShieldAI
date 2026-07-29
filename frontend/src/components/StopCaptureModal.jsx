import React from "react";
import { AlertTriangle, Square, X } from "lucide-react";

const StopCaptureModal = ({ isOpen, onClose, onConfirm }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        
        {/* Header */}
        <div className="p-6 pb-4 flex items-start gap-4">
          <div className="p-3 bg-rose-500/10 text-rose-400 rounded-xl border border-rose-500/20 shrink-0">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div className="flex-1">
            <h3 className="text-lg font-bold text-slate-100">Stop Network Monitoring?</h3>
            <p className="text-xs text-slate-400 mt-1">
              Live traffic packet capture and real-time ML anomaly detection will be paused.
            </p>
          </div>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-slate-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Details */}
        <div className="px-6 py-3 bg-slate-950/50 border-y border-slate-800 text-xs text-slate-300 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Action Impact:</span>
            <span className="font-semibold text-rose-400">Ingestion Paused</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Active Connections:</span>
            <span className="font-semibold text-slate-200">Saved to PostgreSQL</span>
          </div>
        </div>

        {/* Footer buttons */}
        <div className="p-6 pt-4 flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl text-xs font-semibold transition"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              onConfirm();
              onClose();
            }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-rose-600/20 transition"
          >
            <Square className="w-3.5 h-3.5 fill-current" />
            Stop Capture
          </button>
        </div>

      </div>
    </div>
  );
};

export default StopCaptureModal;
