import React, { useEffect, useState } from "react";
import { 
  Layers, 
  Cpu, 
  CheckCircle2, 
  AlertCircle, 
  RefreshCw, 
  FileCode, 
  HardDrive, 
  Calendar, 
  BarChart2, 
  Sliders, 
  ChevronRight,
  Info
} from "lucide-react";
import { modelService } from "../services/api";

const ModelInfo = () => {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [datasetFilter, setDatasetFilter] = useState("ALL");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [selectedModel, setSelectedModel] = useState(null);

  const fetchModelDetails = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await modelService.getModelsInfo();
      setModels(data);
      if (data && data.length > 0) {
        setSelectedModel(data[0]);
      }
    } catch (err) {
      console.error("Failed to load model details:", err);
      setError("Could not retrieve model details from the backend server.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchModelDetails();
  }, []);

  const filteredModels = models.filter((m) => {
    const matchesDataset = datasetFilter === "ALL" || m.dataset === datasetFilter;
    const matchesType = 
      typeFilter === "ALL" || 
      (typeFilter === "ANOMALY" && m.task_type.includes("Anomaly")) ||
      (typeFilter === "BINARY" && m.task_type.includes("Binary")) ||
      (typeFilter === "MULTICLASS" && m.task_type.includes("Multiclass")) ||
      (typeFilter === "PREPROCESSOR" && m.task_type.includes("Preprocessing"));
    return matchesDataset && matchesType;
  });

  const formatPct = (val) => {
    if (val === null || val === undefined) return "N/A";
    return `${(val * 100).toFixed(2)}%`;
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-slate-900/60 p-6 rounded-2xl border border-slate-800 backdrop-blur-md">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-slate-100">Machine Learning Model Architecture</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Phase 5 Verified
            </span>
          </div>
          <p className="text-slate-400 text-sm mt-1">
            Real training parameters, file artifacts, and evaluation metrics for NetShield AI detection pipelines.
          </p>
        </div>

        <button
          onClick={fetchModelDetails}
          disabled={loading}
          className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-sm font-medium transition duration-150 shrink-0"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-indigo-400" : ""}`} />
          Refresh Models
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/50 p-5 rounded-xl border border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Models</span>
            <div className="p-2 bg-indigo-500/10 text-indigo-400 rounded-lg">
              <Cpu className="w-5 h-5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-100 mt-2">{models.length}</p>
          <p className="text-xs text-slate-400 mt-1">6 Inference + 2 Preprocessors</p>
        </div>

        <div className="bg-slate-900/50 p-5 rounded-xl border border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Top Binary Accuracy</span>
            <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg">
              <CheckCircle2 className="w-5 h-5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-emerald-400 mt-2">99.46%</p>
          <p className="text-xs text-slate-400 mt-1">CICIDS2017 XGBoost Binary</p>
        </div>

        <div className="bg-slate-900/50 p-5 rounded-xl border border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Datasets Evaluated</span>
            <div className="p-2 bg-purple-500/10 text-purple-400 rounded-lg">
              <Layers className="w-5 h-5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-purple-400 mt-2">2 Profiles</p>
          <p className="text-xs text-slate-400 mt-1">CICIDS2017 & UNSW-NB15</p>
        </div>

        <div className="bg-slate-900/50 p-5 rounded-xl border border-slate-800/80">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Engine Version</span>
            <div className="p-2 bg-amber-500/10 text-amber-400 rounded-lg">
              <BarChart2 className="w-5 h-5" />
            </div>
          </div>
          <p className="text-2xl font-bold text-slate-100 mt-2">v1.0</p>
          <p className="text-xs text-slate-400 mt-1">Unified Threat Pipeline</p>
        </div>
      </div>

      {/* Filtering Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/40 p-4 rounded-xl border border-slate-800">
        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Dataset:</span>
          {["ALL", "CICIDS2017", "UNSW-NB15"].map((ds) => (
            <button
              key={ds}
              onClick={() => setDatasetFilter(ds)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                datasetFilter === ds
                  ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/20"
                  : "bg-slate-800/80 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              {ds}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Task Type:</span>
          {[
            { label: "All Types", val: "ALL" },
            { label: "Anomaly", val: "ANOMALY" },
            { label: "Binary", val: "BINARY" },
            { label: "Multiclass", val: "MULTICLASS" },
            { label: "Preprocessor", val: "PREPROCESSOR" },
          ].map((t) => (
            <button
              key={t.val}
              onClick={() => setTypeFilter(t.val)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                typeFilter === t.val
                  ? "bg-purple-600 text-white shadow-md shadow-purple-600/20"
                  : "bg-slate-800/80 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Content Layout */}
      {loading ? (
        <div className="h-64 flex items-center justify-center bg-slate-900/40 rounded-xl border border-slate-800">
          <div className="flex items-center gap-3 text-slate-400">
            <RefreshCw className="w-6 h-6 animate-spin text-indigo-400" />
            <span>Loading training model details...</span>
          </div>
        </div>
      ) : error ? (
        <div className="p-6 bg-red-950/20 border border-red-800/50 rounded-xl text-red-400 flex items-center gap-3">
          <AlertCircle className="w-6 h-6 shrink-0" />
          <span>{error}</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Models List Table */}
          <div className="lg:col-span-2 bg-slate-900/50 rounded-xl border border-slate-800 overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-200">Registered Model Artifacts</h3>
              <span className="text-xs text-slate-400">Showing {filteredModels.length} models</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3.5 px-4">Model & Dataset</th>
                    <th className="py-3.5 px-4">Artifact File</th>
                    <th className="py-3.5 px-4">Accuracy</th>
                    <th className="py-3.5 px-4">F1 Score</th>
                    <th className="py-3.5 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {filteredModels.map((m) => {
                    const isSelected = selectedModel?.id === m.id;
                    return (
                      <tr
                        key={m.id}
                        onClick={() => setSelectedModel(m)}
                        className={`cursor-pointer transition hover:bg-slate-800/50 ${
                          isSelected ? "bg-indigo-950/30 border-l-2 border-l-indigo-500" : ""
                        }`}
                      >
                        <td className="py-3.5 px-4">
                          <div className="font-semibold text-slate-100">{m.name}</div>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300 border border-slate-700">
                              {m.dataset}
                            </span>
                            <span className="text-[11px] text-slate-400">{m.task_type}</span>
                          </div>
                        </td>

                        <td className="py-3.5 px-4">
                          <div className="flex items-center gap-1.5 font-mono text-[11px] text-indigo-300">
                            <FileCode className="w-3.5 h-3.5 shrink-0" />
                            {m.file_name}
                          </div>
                          <div className="text-[10px] text-slate-400 mt-0.5">
                            {m.file_size_formatted} ({m.feature_count} features)
                          </div>
                        </td>

                        <td className="py-3.5 px-4 font-mono font-medium">
                          {m.metrics.accuracy !== null && m.metrics.accuracy !== undefined ? (
                            <span className="text-emerald-400">{formatPct(m.metrics.accuracy)}</span>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>

                        <td className="py-3.5 px-4 font-mono font-medium">
                          {m.metrics.f1_score !== null && m.metrics.f1_score !== undefined ? (
                            <span className="text-purple-400">{formatPct(m.metrics.f1_score)}</span>
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </td>

                        <td className="py-3.5 px-4 text-right">
                          <button className="p-1 rounded bg-slate-800 text-slate-300 hover:text-white">
                            <ChevronRight className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Model Detail Inspector Panel */}
          <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-5 space-y-5">
            {selectedModel ? (
              <>
                <div className="border-b border-slate-800 pb-4">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                      {selectedModel.dataset}
                    </span>
                    <span className="text-xs text-slate-400 font-mono">{selectedModel.model_type}</span>
                  </div>
                  <h3 className="text-lg font-bold text-slate-100">{selectedModel.name}</h3>
                  <p className="text-xs text-slate-400 mt-1 font-mono break-all">{selectedModel.file_path}</p>
                </div>

                {/* File & Storage Metrics */}
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                    <HardDrive className="w-3.5 h-3.5 text-indigo-400" /> Artifact Storage
                  </h4>
                  <div className="grid grid-cols-2 gap-2 text-xs bg-slate-950/50 p-3 rounded-lg border border-slate-800/80">
                    <div>
                      <span className="text-slate-400 block">File Size:</span>
                      <span className="font-mono font-medium text-slate-200">{selectedModel.file_size_formatted}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block">Features Expected:</span>
                      <span className="font-mono font-medium text-slate-200">{selectedModel.feature_count} Columns</span>
                    </div>
                    {selectedModel.last_modified && (
                      <div className="col-span-2 mt-1 pt-1 border-t border-slate-800/60">
                        <span className="text-slate-400 block">Last Modified:</span>
                        <span className="font-mono text-[11px] text-slate-300">
                          {new Date(selectedModel.last_modified).toLocaleString()}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Evaluation Metrics Breakdown */}
                {selectedModel.metrics && (selectedModel.metrics.accuracy !== null || selectedModel.metrics.f1_score !== null) ? (
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                      <BarChart2 className="w-3.5 h-3.5 text-emerald-400" /> Evaluation Metrics (Test Split)
                    </h4>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/80">
                        <span className="text-slate-400 block">Accuracy:</span>
                        <span className="text-emerald-400 font-mono font-bold text-sm">
                          {formatPct(selectedModel.metrics.accuracy)}
                        </span>
                      </div>
                      <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/80">
                        <span className="text-slate-400 block">F1 Score:</span>
                        <span className="text-purple-400 font-mono font-bold text-sm">
                          {formatPct(selectedModel.metrics.f1_score)}
                        </span>
                      </div>
                      <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/80">
                        <span className="text-slate-400 block">Precision:</span>
                        <span className="text-indigo-400 font-mono font-bold text-sm">
                          {formatPct(selectedModel.metrics.precision)}
                        </span>
                      </div>
                      <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/80">
                        <span className="text-slate-400 block">Detection Rate (Recall):</span>
                        <span className="text-amber-400 font-mono font-bold text-sm">
                          {formatPct(selectedModel.metrics.recall)}
                        </span>
                      </div>
                      <div className="bg-slate-950/50 p-3 rounded-lg border border-slate-800/80 col-span-2 flex justify-between items-center">
                        <span className="text-slate-400">False Positive Rate (FPR):</span>
                        <span className="text-rose-400 font-mono font-bold">
                          {formatPct(selectedModel.metrics.false_positive_rate)}
                        </span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-3 bg-slate-950/40 rounded-lg border border-slate-800 text-xs text-slate-400 flex items-center gap-2">
                    <Info className="w-4 h-4 text-indigo-400 shrink-0" />
                    <span>Feature preprocessor artifact (no direct accuracy metric).</span>
                  </div>
                )}

                {/* Hyperparameters if present */}
                {selectedModel.training_parameters && Object.keys(selectedModel.training_parameters).length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Sliders className="w-3.5 h-3.5 text-purple-400" /> Training Hyperparameters
                    </h4>
                    <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/80 space-y-1 font-mono text-xs">
                      {Object.entries(selectedModel.training_parameters).map(([k, v]) => (
                        <div key={k} className="flex justify-between border-b border-slate-800/40 py-0.5 last:border-0">
                          <span className="text-slate-400">{k}:</span>
                          <span className="text-indigo-300 font-semibold">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="text-slate-400 text-xs text-center py-10">Select a model from the list to view specifications.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default ModelInfo;
