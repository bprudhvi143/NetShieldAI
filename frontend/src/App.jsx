import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

// Layouts and components
import DashboardLayout from "./layouts/DashboardLayout";
import ProtectedRoute from "./components/ProtectedRoute";

// Pages
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Sniffer from "./pages/Sniffer";
import Datasets from "./pages/Datasets";
import ModelInfo from "./pages/ModelInfo";
import Pipeline from "./pages/Pipeline";
import AuditLogs from "./pages/AuditLogs";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public auth routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Protected general routes (Admins and Analysts) */}
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <DashboardLayout>
                <Dashboard />
              </DashboardLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/sniffer"
          element={
            <ProtectedRoute>
              <DashboardLayout>
                <Sniffer />
              </DashboardLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/datasets"
          element={
            <ProtectedRoute>
              <DashboardLayout>
                <Datasets />
              </DashboardLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/models"
          element={
            <ProtectedRoute>
              <DashboardLayout>
                <ModelInfo />
              </DashboardLayout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/pipeline"
          element={
            <ProtectedRoute>
              <DashboardLayout>
                <Pipeline />
              </DashboardLayout>
            </ProtectedRoute>
          }
        />

        {/* Protected Admin-only routes */}
        <Route
          path="/audit-logs"
          element={
            <ProtectedRoute allowedRoles={["Security Admin"]}>
              <DashboardLayout>
                <AuditLogs />
              </DashboardLayout>
            </ProtectedRoute>
          }
        />

        {/* Wildcard fallback redirection */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
