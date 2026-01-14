import axios from 'axios';

// Backend API base URL
const API_BASE_URL = 'http://127.0.0.1:5000';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 120000, // 120 seconds timeout for thorough scanning
});

// API endpoints
export const apiEndpoints = {
  welcome: '/',
  health: '/api/health',
  analyzeWebsite: '/api/analyze',
  scanXSS: '/api/scan-xss',
  scanSQLi: '/api/scan-sqli',
};

// API functions
export const checkHealth = async () => {
  try {
    const response = await api.get(apiEndpoints.health);
    return response.data;
  } catch (error) {
    console.error('Health check failed:', error);
    throw error;
  }
};

export const analyzeWebsite = async (url, selectedTests = null) => {
  try {
    const payload = { url };
    if (selectedTests) {
      payload.tests = selectedTests;
    }
    const response = await api.post(apiEndpoints.analyzeWebsite, payload);
    return response.data;
  } catch (error) {
    console.error('Website analysis failed:', error);
    throw error;
  }
};

export const scanXSSVulnerability = async (url) => {
  try {
    const response = await api.post(apiEndpoints.scanXSS, { url });
    return response.data;
  } catch (error) {
    console.error('XSS scan failed:', error);
    throw error;
  }
};

export const scanSQLInjection = async (url, param = null, method = 'GET') => {
  try {
    const response = await api.post(apiEndpoints.scanSQLi, { url, param, method });
    return response.data;
  } catch (error) {
    console.error('SQL injection scan failed:', error);
    throw error;
  }
};

export default api;
