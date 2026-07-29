import React from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { 
  Activity, 
  Radio, 
  Database, 
  Layers,
  GitCommit,
  ShieldAlert, 
  LogOut, 
  User, 
  Shield 
} from "lucide-react";
import { authService } from "../services/api";

const DashboardLayout = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const user = authService.getUser();
  const isAdmin = user?.role?.name === "Security Admin";

  const handleLogout = () => {
    authService.logout();
    navigate("/login");
  };

  const navItems = [
    { name: "Dashboard", path: "/dashboard", icon: Activity, show: true },
    { name: "Packet Sniffer", path: "/sniffer", icon: Radio, show: true },
    { name: "Dataset Profiler", path: "/datasets", icon: Database, show: true },
    { name: "Model Architecture", path: "/models", icon: Layers, show: true },
    { name: "Detection Pipeline", path: "/pipeline", icon: GitCommit, show: true },
    { name: "Audit Logs", path: "/audit-logs", icon: ShieldAlert, show: isAdmin },
  ];

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden text-slate-100">
      {/* Sidebar navigation */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between shrink-0">
        <div>
          {/* Logo */}
          <div className="h-16 flex items-center gap-3 px-6 border-b border-slate-800">
            <Shield className="w-8 h-8 text-indigo-500 fill-indigo-500/10" />
            <span className="text-xl font-bold tracking-wider bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
              NETSHIELD AI
            </span>
          </div>
          
          {/* Nav Links */}
          <nav className="mt-6 px-4 space-y-1">
            {navItems.map(
              (item) =>
                item.show && (
                  <Link
                    key={item.name}
                    to={item.path}
                    className={`flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition duration-150 ${
                      location.pathname === item.path
                        ? "bg-indigo-600 text-white shadow-lg shadow-indigo-600/20"
                        : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                    }`}
                  >
                    <item.icon className="w-5 h-5 shrink-0" />
                    {item.name}
                  </Link>
                )
            )}
          </nav>
        </div>

        {/* User Card */}
        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center gap-3 p-2 bg-slate-950/40 rounded-xl border border-slate-800/60 mb-3">
            <div className="w-9 h-9 bg-slate-800 border border-slate-700 rounded-full flex items-center justify-center text-slate-300">
              <User className="w-5 h-5" />
            </div>
            <div className="overflow-hidden">
              <p className="text-xs font-semibold text-slate-200 truncate">
                {user?.full_name || "Security Analyst"}
              </p>
              <div className="flex items-center gap-1 mt-0.5">
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider ${
                  isAdmin ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20"
                }`}>
                  {user?.role?.name || "Analyst"}
                </span>
              </div>
            </div>
          </div>
          
          {/* Logout */}
          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-slate-800/80 hover:bg-red-900/20 hover:text-red-400 hover:border-red-950 border border-slate-700/60 text-slate-300 rounded-lg text-sm font-medium transition duration-200"
          >
            <LogOut className="w-4 h-4" />
            Logout Session
          </button>
        </div>
      </aside>

      {/* Main View Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header */}
        <header className="h-16 bg-slate-900/50 border-b border-slate-800 flex items-center justify-between px-8 backdrop-blur-md shrink-0">
          <h2 className="text-lg font-semibold tracking-tight text-slate-100">
            {navItems.find((item) => item.path === location.pathname)?.name || "System"}
          </h2>
          <div className="text-xs text-slate-400 font-mono">
            Platform Engine: <span className="text-indigo-400 font-semibold">FastAPI v1.0</span> | DB: <span className="text-indigo-400 font-semibold">Postgres + MongoDB</span>
          </div>
        </header>

        {/* Content body */}
        <main className="flex-1 overflow-y-auto p-8 bg-slate-950">
          <div className="max-w-7xl mx-auto h-full">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
