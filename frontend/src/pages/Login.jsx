import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Shield, Eye, EyeOff, AlertTriangle, Cpu, Terminal, Key, Radio, ShieldCheck, ChevronRight, User } from "lucide-react";
import { authService } from "../services/api";
import loginBanner from "../assets/netshield_login_banner.png";

const Login = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email || !password) {
      setError("Please fill in all fields.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      // 1. Send Login credentials
      await authService.login(email, password);
      // 2. Fetch User profile detail to save in storage
      await authService.getCurrentUser();
      // 3. Navigate to dashboard
      navigate("/dashboard");
    } catch (err) {
      const errMsg = err.response?.data?.detail || "Connection to backend server failed.";
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  const autofillAdmin = () => {
    setEmail("admin@netshield.ai");
    setPassword("AdminNetShield123!");
    setError("");
  };

  const autofillAnalyst = () => {
    setEmail("analyst@netshield.ai");
    setPassword("AnalystNetShield123!");
    setError("");
  };

  return (
    <div className="min-h-screen flex bg-slate-950 text-slate-100 overflow-hidden relative">
      {/* Background Gradients */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/10 rounded-full blur-[120px] pointer-events-none z-0"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-purple-600/10 rounded-full blur-[120px] pointer-events-none z-0"></div>

      {/* Left Column: Visual Showcase (Hidden on Mobile/Tablet) */}
      <div className="hidden lg:flex lg:w-7/12 flex-col justify-between p-12 bg-slate-900/40 border-r border-slate-800/60 relative overflow-hidden z-10">
        {/* Subtle grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-20 pointer-events-none"></div>

        {/* Top Header Logo */}
        <div className="flex items-center gap-3 relative z-10">
          <div className="w-10 h-10 bg-indigo-600/20 border border-indigo-500/40 rounded-xl flex items-center justify-center text-indigo-400">
            <Shield className="w-5 h-5 fill-indigo-500/10" />
          </div>
          <span className="text-xl font-bold tracking-widest bg-gradient-to-r from-indigo-400 via-purple-400 to-indigo-500 bg-clip-text text-transparent">
            NETSHIELD AI
          </span>
        </div>

        {/* Mid Section: Interactive Banner & Graphic */}
        <div className="my-auto relative z-10 space-y-8">
          <div className="space-y-4 max-w-xl">
            <h1 className="text-4xl font-extrabold tracking-tight leading-tight text-slate-100">
              Intelligent Network Anomaly Detection & Threat Prevention Engine
            </h1>
            <p className="text-slate-400 text-sm leading-relaxed">
              Ingest packet logs, classify network payloads, and analyze suspicious behavior in real-time. NetShield AI empowers SOC teams with predictive security capabilities.
            </p>
          </div>

          {/* Interactive banner graphic mockup */}
          <div className="relative group max-w-2xl rounded-2xl overflow-hidden border border-slate-700/50 shadow-2xl shadow-indigo-500/5 bg-slate-950">
            <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-transparent to-transparent opacity-65 z-10"></div>
            <img 
              src={loginBanner} 
              alt="NetShield AI Command Center Console Visualization" 
              className="w-full h-auto object-cover transform group-hover:scale-105 transition duration-700 opacity-90"
            />
            {/* Overlay indicators */}
            <div className="absolute bottom-4 left-6 right-6 z-20 flex justify-between items-center">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                <span className="text-xs font-mono text-slate-300 font-bold uppercase tracking-wider">Engine Status: ACTIVE</span>
              </div>
              <div className="text-[10px] font-mono text-indigo-400 bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded">
                ML CLASSIFICATION v2.4
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Feature Highlights */}
        <div className="grid grid-cols-2 gap-6 pt-6 border-t border-slate-800/60 relative z-10">
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center shrink-0 text-indigo-400">
              <Radio className="w-4 h-4" />
            </div>
            <div>
              <h4 className="text-xs font-semibold text-slate-200">Ingress Capturing</h4>
              <p className="text-[11px] text-slate-500 mt-0.5">Wire-speed packet sniffing via live emulators.</p>
            </div>
          </div>

          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center shrink-0 text-purple-400">
              <Cpu className="w-4 h-4" />
            </div>
            <div>
              <h4 className="text-xs font-semibold text-slate-200">ML Predictions</h4>
              <p className="text-[11px] text-slate-500 mt-0.5">Automated intrusion profiling via UNSW-NB15.</p>
            </div>
          </div>
        </div>
      </div>

      {/* Right Column: Glassmorphic Auth Card */}
      <div className="w-full lg:w-5/12 flex items-center justify-center p-6 sm:p-12 relative z-10">
        <div className="w-full max-w-md bg-slate-900/60 border border-slate-800/80 rounded-3xl p-8 sm:p-10 shadow-2xl backdrop-blur-2xl relative">
          
          {/* Mobile Header Logo */}
          <div className="flex flex-col items-center mb-8 lg:hidden">
            <div className="w-12 h-12 bg-indigo-600/10 border border-indigo-500/30 text-indigo-400 rounded-2xl flex items-center justify-center mb-3">
              <Shield className="w-6 h-6 fill-indigo-500/10" />
            </div>
            <h1 className="text-2xl font-bold tracking-wider text-slate-100">NETSHIELD AI</h1>
          </div>

          {/* Form Title */}
          <div className="mb-8 text-center lg:text-left">
            <h2 className="text-2xl font-bold text-slate-100">Authenticate Session</h2>
            <p className="text-xs text-slate-400 mt-1.5">Provide secure credentials to establish a monitor session</p>
          </div>

          {/* Error Message */}
          {error && (
            <div className="flex items-start gap-3 p-4 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-xs mb-6 animate-shake">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <p className="leading-relaxed">{error}</p>
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">
                Security Profile Email
              </label>
              <div className="relative">
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="e.g. analyst@netshield.ai"
                  className="w-full px-4 py-3 bg-slate-950/80 border border-slate-800 hover:border-slate-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-slate-200 placeholder-slate-700 rounded-xl text-sm transition outline-none"
                  required
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                  Access Key / Password
                </label>
              </div>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full px-4 py-3 pr-12 bg-slate-950/80 border border-slate-800 hover:border-slate-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-slate-200 placeholder-slate-700 rounded-xl text-sm transition outline-none"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3.5 top-3.5 text-slate-600 hover:text-slate-350 transition"
                >
                  {showPassword ? <EyeOff className="w-4.5 h-4.5" /> : <Eye className="w-4.5 h-4.5" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3.5 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:from-indigo-800 disabled:to-purple-800 text-white rounded-xl font-semibold transition duration-300 shadow-xl shadow-indigo-600/20 hover:shadow-indigo-600/30 flex items-center justify-center gap-2 text-sm cursor-pointer"
            >
              {loading ? (
                <>
                  <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Initializing Monitor Session...
                </>
              ) : (
                <>
                  Establish Access Session <ChevronRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Sandbox Seeds Section */}
          <div className="mt-8 pt-6 border-t border-slate-800/80 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">💡 Quick Access Sandbox Profiles</span>
            </div>
            
            <div className="grid grid-cols-2 gap-3.5">
              {/* Security Admin Card */}
              <div 
                onClick={autofillAdmin}
                className="p-3 bg-slate-950/60 hover:bg-indigo-950/20 border border-slate-800 hover:border-indigo-500/40 rounded-xl cursor-pointer transition-all duration-200 text-left group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-bold text-indigo-400 uppercase tracking-widest">Admin Control</span>
                  <ShieldCheck className="w-3.5 h-3.5 text-indigo-400 opacity-50 group-hover:opacity-100 transition" />
                </div>
                <p className="text-[11px] font-bold text-slate-200 mt-1 font-mono">admin@netshield.ai</p>
                <p className="text-[9px] text-slate-500 mt-0.5">Full System Access & Audits</p>
              </div>

              {/* Security Analyst Card */}
              <div 
                onClick={autofillAnalyst}
                className="p-3 bg-slate-950/60 hover:bg-purple-950/20 border border-slate-800 hover:border-purple-500/40 rounded-xl cursor-pointer transition-all duration-200 text-left group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-bold text-purple-400 uppercase tracking-widest">Analyst SOC</span>
                  <Radio className="w-3.5 h-3.5 text-purple-400 opacity-50 group-hover:opacity-100 transition" />
                </div>
                <p className="text-[11px] font-bold text-slate-200 mt-1 font-mono">analyst@netshield.ai</p>
                <p className="text-[9px] text-slate-500 mt-0.5">Live Traffic & Threat Hunt</p>
              </div>
            </div>
          </div>

          <p className="text-xs text-center text-slate-500 mt-8">
            Require operational clearance?{" "}
            <Link to="/register" className="text-indigo-400 hover:text-indigo-300 font-semibold transition">
              Register Credentials
            </Link>
          </p>

        </div>
      </div>
    </div>
  );
};

export default Login;

