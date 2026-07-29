import axios from "axios";

// Create Axios client targeting our backend API prefix
const api = axios.create({
  baseURL: "http://localhost:8000/api/v1",
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor: Attach JWT bearer token if it exists in local storage
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers["Authorization"] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor: Handle expired tokens or auth failures automatically
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      // Clear expired auth data
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      // Redirect to login page if we are in browser environment
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

// Authentication services
export const authService = {
  login: async (email, password) => {
    const response = await api.post("/auth/login-json", { email, password });
    if (response.data.access_token) {
      localStorage.setItem("token", response.data.access_token);
    }
    return response.data;
  },
  
  register: async (email, fullName, password, roleName) => {
    const response = await api.post("/auth/register", {
      email,
      full_name: fullName,
      password,
      role_name: roleName,
    });
    return response.data;
  },
  
  getCurrentUser: async () => {
    const response = await api.get("/users/me");
    localStorage.setItem("user", JSON.stringify(response.data));
    return response.data;
  },
  
  logout: () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
  },
  
  getUser: () => {
    const userStr = localStorage.getItem("user");
    return userStr ? JSON.parse(userStr) : null;
  },
  
  getToken: () => {
    return localStorage.getItem("token");
  },
};

// Administrative services (Admins only)
export const adminService = {
  getUsers: async (skip = 0, limit = 100) => {
    const response = await api.get(`/users/?skip=${skip}&limit=${limit}`);
    return response.data;
  },
  
  getAuditLogs: async (skip = 0, limit = 100) => {
    const response = await api.get(`/users/audit-logs?skip=${skip}&limit=${limit}`);
    return response.data;
  },
  
  updateUserRole: async (userId, data) => {
    const response = await api.put(`/users/${userId}`, data);
    return response.data;
  },
};

// Monitoring services
export const monitoringService = {
  getInterfaces: async () => {
    const response = await api.get("/monitoring/interfaces");
    return response.data;
  },

  startSniffer: async (iface = null) => {
    const url = iface ? `/monitoring/start?interface=${encodeURIComponent(iface)}` : "/monitoring/start";
    const response = await api.post(url);
    return response.data;
  },
  
  stopSniffer: async () => {
    const response = await api.post("/monitoring/stop");
    return response.data;
  },
  
  getSnifferStatus: async () => {
    const response = await api.get("/monitoring/status");
    return response.data;
  },
  
  getPackets: async (skip = 0, limit = 100) => {
    const response = await api.get(`/monitoring/packets?skip=${skip}&limit=${limit}`);
    return response.data;
  },
  
  getTrafficSummary: async () => {
    const response = await api.get("/monitoring/summary");
    return response.data;
  },

  getFlows: async (params = {}) => {
    const response = await api.get("/monitoring/flows", { params });
    return response.data;
  },

  getMetrics: async () => {
    const response = await api.get("/monitoring/metrics");
    return response.data;
  },

  getTimeline: async () => {
    const response = await api.get("/monitoring/timeline");
    return response.data;
  },
};

// Dataset services
export const datasetService = {
  triggerSampling: async (datasetName, sampleSize = 5000) => {
    const response = await api.post("/datasets/sample", {
      dataset_name: datasetName,
      sample_size: sampleSize,
    });
    return response.data;
  },
  
  getProfilingReport: async (datasetName) => {
    const response = await api.get(`/datasets/reports/${datasetName}`);
    return response.data;
  },
};

// Model details service
export const modelService = {
  getModelsInfo: async () => {
    const response = await api.get("/models/info");
    return response.data;
  },
};

export default api;
