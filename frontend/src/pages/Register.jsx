import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Shield, CheckCircle, AlertTriangle } from "lucide-react";
import { authService } from "../services/api";

const Register = () => {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [roleName, setRoleName] = useState("Security Analyst");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!fullName || !email || !password || !roleName) {
      setError("Please fill in all fields.");
      return;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      await authService.register(email, fullName, password, roleName);
      setSuccess(true);
      setTimeout(() => {
        navigate("/login");
      }, 2000);
    } catch (err) {
      const errMsg = err.response?.data?.detail || "Registration failed. Try again.";
      setError(errMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 px-4 relative overflow-hidden">
      {/* Background Gradients */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-indigo-600/10 rounded-full blur-[120px] pointer-events-none z-0"></div>
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-purple-600/10 rounded-full blur-[120px] pointer-events-none z-0"></div>

      {/* Main glassmorphic wrapper */}
      <div className="w-full max-w-md bg-slate-900/60 border border-slate-800/80 rounded-3xl p-8 sm:p-10 shadow-2xl backdrop-blur-2xl relative z-10">
        
        {/* Header */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-indigo-600/10 border border-indigo-500/30 text-indigo-400 rounded-2xl flex items-center justify-center mb-3">
            <Shield className="w-6 h-6 fill-indigo-500/10" />
          </div>
          <h1 className="text-2xl font-bold text-slate-100">Create Security Account</h1>
          <p className="text-xs text-slate-450 mt-1">Register a new analyst or admin profile</p>
        </div>

        {/* Success Alert */}
        {success && (
          <div className="flex items-start gap-3 p-4 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl text-xs mb-6">
            <CheckCircle className="w-5 h-5 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">Registration Successful!</p>
              <p className="text-slate-450 mt-0.5">Redirecting to login portal...</p>
            </div>
          </div>
        )}

        {/* Form Error */}
        {error && (
          <div className="flex items-start gap-3 p-3.5 bg-red-500/10 border border-red-500/20 text-red-400 rounded-xl text-xs mb-6">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <p className="leading-relaxed">{error}</p>
          </div>
        )}

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="space-y-4.5">
          <div>
            <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">
              Full Name
            </label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              placeholder="e.g. John Doe"
              className="w-full px-4 py-3 bg-slate-950/80 border border-slate-800 hover:border-slate-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-slate-200 placeholder-slate-700 rounded-xl text-sm transition outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">
              Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="e.g. jdoe@netshield.ai"
              className="w-full px-4 py-3 bg-slate-950/80 border border-slate-800 hover:border-slate-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-slate-200 placeholder-slate-700 rounded-xl text-sm transition outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">
              Assigned Key / Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Min. 8 characters"
              className="w-full px-4 py-3 bg-slate-950/80 border border-slate-800 hover:border-slate-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-slate-200 placeholder-slate-700 rounded-xl text-sm transition outline-none"
              required
            />
          </div>

          <div>
            <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-2">
              Assigned Role
            </label>
            <select
              value={roleName}
              onChange={(e) => setRoleName(e.target.value)}
              className="w-full px-4 py-3 bg-slate-950/80 border border-slate-800 hover:border-slate-700 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 text-slate-200 rounded-xl text-sm transition outline-none cursor-pointer"
              required
            >
              <option value="Security Analyst">Security Analyst</option>
              <option value="Security Admin">Security Admin</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading || success}
            className="w-full py-3.5 mt-2 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 disabled:from-indigo-800 disabled:to-purple-800 text-white rounded-xl font-semibold transition duration-300 shadow-xl shadow-indigo-600/20 hover:shadow-indigo-600/30 flex items-center justify-center gap-2 text-sm cursor-pointer"
          >
            {loading ? (
              <>
                <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Registering Profile...
              </>
            ) : (
              "Initialize Operational Profile"
            )}
          </button>
        </form>

        <p className="text-xs text-center text-slate-500 mt-8">
          Already have credentials?{" "}
          <Link to="/login" className="text-indigo-400 hover:text-indigo-300 font-semibold transition">
            Sign In
          </Link>
        </p>
      </div>
    </div>
  );
};

export default Register;
