import React, { useState, useEffect } from "react";
import { 
  Database, 
  BarChart4, 
  RefreshCw, 
  Check, 
  AlertTriangle, 
  Settings 
} from "lucide-react";
import { datasetService } from "../services/api";

const Datasets = () => {
  const [selectedDataset, setSelectedDataset] = useState("unsw_nb15");
  const [sampleSize, setSampleSize] = useState(5000);
  const [loadingSample, setLoadingSample] = useState(false);
  const [loadingReport, setLoadingReport] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [sampleSuccess, setSampleSuccess] = useState("");

  const fetchReport = async (datasetName) => {
    setLoadingReport(true);
    setError("");
    try {
      const data = await datasetService.getProfilingReport(datasetName);
      setReport(data);
    } catch (err) {
      // If sample has not been generated yet, set report to null and prompt user
      if (err.response?.status === 404) {
        setReport(null);
      } else {
        setError(err.response?.data?.detail || "Failed to load profiling report.");
      }
    } finally {
      setLoadingReport(false);
    }
  };

  const handleGenerateSample = async (e) => {
    e.preventDefault();
    setLoadingSample(true);
    setError("");
    setSampleSuccess("");
    try {
      await datasetService.triggerSampling(selectedDataset, sampleSize);
      setSampleSuccess(`Successfully generated ${sampleSize}-row sample for ${selectedDataset.toUpperCase()}!`);
      // Refresh report
      fetchReport(selectedDataset);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to trigger dataset sampling.");
    } finally {
      setLoadingSample(false);
    }
  };

  useEffect(() => {
    fetchReport(selectedDataset);
  }, [selectedDataset]);

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Control panel card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 lg:col-span-1 h-fit space-y-6">
          <div>
            <h3 className="font-semibold text-slate-200 flex items-center gap-2">
              <Database className="w-5 h-5 text-indigo-500" />
              Dataset Manager
            </h3>
            <p className="text-xs text-slate-400 mt-1">Configure and sample security datasets.</p>
          </div>

          <form onSubmit={handleGenerateSample} className="space-y-5">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                Target Dataset
              </label>
              <select
                value={selectedDataset}
                onChange={(e) => setSelectedDataset(e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-950 border border-slate-800 hover:border-slate-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-slate-200 rounded-xl text-sm transition outline-none cursor-pointer"
              >
                <option value="unsw_nb15">UNSW-NB15 (Headerless CSVs)</option>
                <option value="cicids2017">CICIDS2017 (Standard CSVs)</option>
              </select>
            </div>

            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Sample Rows
                </label>
                <span className="text-xs font-mono text-indigo-400 font-semibold">{sampleSize}</span>
              </div>
              <input
                type="range"
                min="1000"
                max="10000"
                step="500"
                value={sampleSize}
                onChange={(e) => setSampleSize(parseInt(e.target.value))}
                className="w-full h-1 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-indigo-500"
              />
              <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
                <span>1K</span>
                <span>5K (Default)</span>
                <span>10K</span>
              </div>
            </div>

            <button
              type="submit"
              disabled={loadingSample || loadingReport}
              className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800 disabled:text-slate-400 text-white rounded-xl text-sm font-semibold transition flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/10"
            >
              {loadingSample ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" /> Sampling Files...
                </>
              ) : (
                "Draw & Save Sample"
              )}
            </button>
          </form>

          {/* Action Logs */}
          {sampleSuccess && (
            <div className="flex items-start gap-2 p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl text-xs">
              <Check className="w-4 h-4 shrink-0 mt-0.5" />
              <p>{sampleSuccess}</p>
            </div>
          )}

          {error && (
            <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-xs">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <p>{error}</p>
            </div>
          )}
        </div>

        {/* Profiler statistics Display */}
        <div className="lg:col-span-2 space-y-6">
          {loadingReport ? (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center flex flex-col items-center justify-center min-h-[300px]">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-indigo-500 mb-4"></div>
              <p className="text-sm text-slate-400">Loading dataset statistics and profiling summaries...</p>
            </div>
          ) : !report ? (
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center flex flex-col items-center justify-center min-h-[300px] space-y-4">
              <BarChart4 className="w-12 h-12 text-slate-600" />
              <h4 className="font-semibold text-slate-200">No Sample Profiled Yet</h4>
              <p className="text-xs text-slate-400 max-w-md">
                We could not locate the preprocessed sample file for <strong>{selectedDataset.toUpperCase()}</strong>. 
                Click "Draw & Save Sample" on the left to extract the CSV and generate reports.
              </p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Stats overview cards */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Processed Rows</p>
                  <p className="text-xl font-bold text-slate-200 mt-1">{report.statistics.num_rows}</p>
                </div>
                <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Feature Dimension</p>
                  <p className="text-xl font-bold text-slate-200 mt-1">{report.statistics.num_columns} Columns</p>
                </div>
                <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl col-span-2 sm:col-span-1">
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">File Size</p>
                  <p className="text-xl font-bold text-slate-200 mt-1">{report.statistics.memory_usage_mb} MB</p>
                </div>
              </div>

              {/* Class Distributions */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
                <div>
                  <h4 className="font-semibold text-slate-200">Class Label Distributions</h4>
                  <p className="text-[10px] text-slate-500 mt-0.5">Frequency count in the processed file</p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="bg-slate-950/40 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
                        <th className="py-2.5 px-4">Label</th>
                        <th className="py-2.5 px-4 text-center">Packets</th>
                        <th className="py-2.5 px-4 text-right">Percentage</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {Object.entries(report.class_distribution).map(([cls, value]) => (
                        <tr key={cls} className="hover:bg-slate-800/10">
                          <td className="py-2 px-4 font-mono font-semibold">
                            {cls === "0" || cls.toLowerCase() === "benign" ? "🛡️ Benign (Normal)" : `⚠️ Intrusion (${cls})`}
                          </td>
                          <td className="py-2 px-4 text-center font-mono">{value.count}</td>
                          <td className="py-2 px-4 text-right font-mono text-indigo-400 font-semibold">
                            {value.percentage}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Multi-class categories for UNSW */}
              {selectedDataset === "unsw_nb15" && report.attack_categories_distribution && (
                <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-4">
                  <div>
                    <h4 className="font-semibold text-slate-200">Attack Type Details (Multi-Class)</h4>
                    <p className="text-[10px] text-slate-500 mt-0.5">Visual profiling of threat categories</p>
                  </div>
                  <div className="space-y-3">
                    {Object.entries(report.attack_categories_distribution).map(([cat, val]) => (
                      <div key={cat} className="space-y-1">
                        <div className="flex justify-between text-xs font-medium text-slate-300">
                          <span className="capitalize">{cat === "nan" ? "Normal / Safe" : cat}</span>
                          <span className="font-mono text-slate-400">{val.count} packets ({val.percentage}%)</span>
                        </div>
                        <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                          <div 
                            className={`h-full rounded-full ${
                              cat === "nan" ? "bg-emerald-500" : "bg-purple-500"
                            }`}
                            style={{ width: `${val.percentage}%` }}
                          ></div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Datasets;
