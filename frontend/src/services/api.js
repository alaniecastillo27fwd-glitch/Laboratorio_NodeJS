const API_BASE_URL = (import.meta.env.VITE_API_URL || 'http://localhost:3000').replace(/\/$/, '');

/**
 * Wrapper seguro de fetch (OWASP A02 / A05 / A07).
 * - Envía automáticamente cookies HttpOnly (credentials: 'include').
 * - Jamás almacena ni lee tokens desde localStorage o sessionStorage.
 */
export const apiRequest = async (endpoint, options = {}) => {
  const { method = 'GET', body, headers = {} } = options;

  const config = {
    method,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  };

  if (body !== undefined) {
    config.body = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

  let data = null;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    data = await response.json();
  }

  if (!response.ok) {
    const error = new Error(
      data?.error ||
        (response.status === 429
          ? 'Demasiados intentos. Por favor, espere antes de volver a intentar.'
          : 'Error en la solicitud')
    );
    error.status = response.status;
    error.details = data?.details || [];
    throw error;
  }

  return data;
};

export const api = {
  // Autenticación (RF-01, RF-02, RF-06)
  register: (payload) => apiRequest('/api/auth/register', { method: 'POST', body: payload }),
  login: (payload) => apiRequest('/api/auth/login', { method: 'POST', body: payload }),
  logout: () => apiRequest('/api/auth/logout', { method: 'POST' }),
  forgotPassword: (payload) =>
    apiRequest('/api/auth/forgot-password', { method: 'POST', body: payload }),
  resetPassword: (payload) =>
    apiRequest('/api/auth/reset-password', { method: 'POST', body: payload }),

  // Perfil y dato sensible cifrado (RF-05)
  getProfile: (reveal = false) =>
    apiRequest(`/api/profile${reveal ? '?reveal=true' : ''}`, { method: 'GET' }),
  updateSensitiveData: (sensitiveData) =>
    apiRequest('/api/profile/sensitive', { method: 'PUT', body: { sensitiveData } }),

  // CRUD Notas Privadas Cifradas (RF-04)
  listNotes: () => apiRequest('/api/notes', { method: 'GET' }),
  getNote: (id) => apiRequest(`/api/notes/${encodeURIComponent(id)}`, { method: 'GET' }),
  createNote: (payload) => apiRequest('/api/notes', { method: 'POST', body: payload }),
  updateNote: (id, payload) =>
    apiRequest(`/api/notes/${encodeURIComponent(id)}`, { method: 'PUT', body: payload }),
  deleteNote: (id) => apiRequest(`/api/notes/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // Panel de Administración (RF-07)
  listUsers: () => apiRequest('/api/admin/users', { method: 'GET' }),
  changeUserRole: (id, role) =>
    apiRequest(`/api/admin/users/${encodeURIComponent(id)}/role`, {
      method: 'PATCH',
      body: { role },
    }),
  listAuditLogs: () => apiRequest('/api/admin/audit-logs', { method: 'GET' }),
};
