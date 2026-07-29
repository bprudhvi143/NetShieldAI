import React from "react";
import { Navigate } from "react-router-dom";
import { authService } from "../services/api";

const ProtectedRoute = ({ children, allowedRoles }) => {
  const token = authService.getToken();
  const user = authService.getUser();

  // If not logged in, bounce to login
  if (!token || !user) {
    return <Navigate to="/login" replace />;
  }

  // If role checking is needed and user role is not allowed, show Access Denied
  if (allowedRoles && !allowedRoles.includes(user.role.name)) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-8 bg-slate-900/50 border border-red-500/20 rounded-2xl max-w-2xl mx-auto my-12 backdrop-blur-md">
        <div className="w-16 h-16 bg-red-500/10 border border-red-500/30 text-red-400 rounded-full flex items-center justify-center mb-6 text-2xl font-bold">
          !
        </div>
        <h1 className="text-2xl font-semibold text-slate-100 mb-2">Access Denied</h1>
        <p className="text-slate-400 mb-6">
          You do not have the required security clearances to view this page. This page requires a 
          <strong> {allowedRoles.join(" or ")}</strong> role, but you are currently logged in as a 
          <strong> {user.role.name}</strong>.
        </p>
        <button
          onClick={() => (window.location.href = "/dashboard")}
          className="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 hover:border-slate-600 rounded-lg font-medium transition duration-200"
        >
          Return to Dashboard
        </button>
      </div>
    );
  }

  return children;
};

export default ProtectedRoute;
