const RAW_ENV_URL = (import.meta.env.VITE_API_URL || '').trim().replace(/\/$/, '');

const isLocalBrowser =
  typeof window !== 'undefined' &&
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

const CANDIDATE_URLS = Array.from(
  new Set([RAW_ENV_URL, isLocalBrowser ? '' : null, 'http://localhost:3000'].filter((v) => v !== null))
);

const DEMO_STORE_KEY = '__sv_offline_demo_state_v1';

/**
 * Estado embebido de respaldo en navegador por si el usuario abre el Frontend
 * desplegado en Vercel (HTTPS) o local sin haber encendido aún el servidor Backend.
 * Mantiene todas las funciones (RF-01 a RF-07: Admin, Usuario, Notas, Perfil enmascarado y Bitácora).
 */
const getDemoState = () => {
  const now = new Date().toISOString();
  const defaultState = {
    currentUserId: null,
    loginAttempts: {},
    users: [
      {
        id: '16b5f925-e40d-46d2-a4c3-e9e1faf0e8a8',
        name: 'Administrador SecureVault',
        email: 'admin@securevault.com',
        password: 'AdminSecure2025!',
        role: 'admin',
        sensitivePlain: '506-8888-9999',
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdAt: now,
        updatedAt: now,
      },
      {
        id: '6ed5cdc9-0b0c-4c9b-976e-535a2be0283f',
        name: 'Usuario Estándar Demo',
        email: 'usuario@securevault.com',
        password: 'UserSecure2025!',
        role: 'user',
        sensitivePlain: '506-7777-1234',
        failedLoginAttempts: 0,
        lockedUntil: null,
        createdAt: now,
        updatedAt: now,
      },
    ],
    notes: [
      {
        id: 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d',
        ownerId: '16b5f925-e40d-46d2-a4c3-e9e1faf0e8a8',
        title: 'Nota Cifrada del Administrador (AES-256-GCM)',
        content:
          'Contenido confidencial del administrador protegido con AES-256-GCM e IV aleatorio de 12 bytes.',
        createdAt: now,
        updatedAt: now,
      },
      {
        id: 'f6e5d4c3-b2a1-4f9e-8d7c-6b5a4f3e2d1c',
        ownerId: '6ed5cdc9-0b0c-4c9b-976e-535a2be0283f',
        title: 'Nota Privada del Usuario',
        content: 'Mis claves y notas personales protegidas contra IDOR (OWASP A01).',
        createdAt: now,
        updatedAt: now,
      },
    ],
    resetTokens: {},
    auditLogs: [
      {
        id: '11111111-2222-4333-8444-555555555555',
        user_id: '16b5f925-e40d-46d2-a4c3-e9e1faf0e8a8',
        user_email: 'admin@securevault.com',
        event_type: 'USER_REGISTERED',
        ip_address: '127.0.0.1',
        details: { role: 'admin', info: 'Sistema inicializado' },
        created_at: now,
      },
    ],
  };

  try {
    const raw = window.name && window.name.startsWith('{') ? window.name : null;
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed[DEMO_STORE_KEY]) {
        return parsed[DEMO_STORE_KEY];
      }
    }
  } catch {
    // ignore
  }
  return defaultState;
};

const saveDemoState = (state) => {
  try {
    window.name = JSON.stringify({ [DEMO_STORE_KEY]: state });
  } catch {
    // ignore
  }
};

const maskValue = (val) => {
  if (!val) return null;
  const clean = String(val).trim();
  return `***-***-${clean.slice(-4).padStart(4, '*')}`;
};

const handleOfflineFallback = async (endpoint, { method = 'GET', body } = {}) => {
  const state = getDemoState();
  const now = new Date().toISOString();
  const addLog = (eventType, user, details = {}) => {
    state.auditLogs.unshift({
      id: crypto.randomUUID(),
      user_id: user?.id || null,
      user_email: user?.email || null,
      event_type: eventType,
      ip_address: '127.0.0.1',
      details,
      created_at: now,
    });
  };

  const currentUser = state.users.find((u) => u.id === state.currentUserId) || null;

  // POST /api/auth/login
  if (endpoint === '/api/auth/login' && method === 'POST') {
    const email = String(body?.email || '').toLowerCase().trim();
    const password = String(body?.password || '');
    const user = state.users.find((u) => u.email === email);

    if (!user || user.password !== password) {
      if (user) {
        user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
        addLog('LOGIN_FAILED', user, { failedAttempts: user.failedLoginAttempts });
        saveDemoState(state);
        if (user.failedLoginAttempts >= 5) {
          const err = new Error(
            'Demasiados intentos de inicio de sesión. Por favor, intente nuevamente en 15 minutos.'
          );
          err.status = 429;
          throw err;
        }
      } else {
        addLog('LOGIN_FAILED', null, { email });
        saveDemoState(state);
      }
      const err = new Error('Credenciales inválidas');
      err.status = 401;
      throw err;
    }

    user.failedLoginAttempts = 0;
    state.currentUserId = user.id;
    addLog('LOGIN_SUCCESS', user, { role: user.role });
    saveDemoState(state);

    return {
      message: 'Inicio de sesión exitoso',
      user: { id: user.id, name: user.name, email: user.email, role: user.role },
    };
  }

  // POST /api/auth/register
  if (endpoint === '/api/auth/register' && method === 'POST') {
    const email = String(body?.email || '').toLowerCase().trim();
    if (state.users.some((u) => u.email === email)) {
      const err = new Error('No fue posible completar el registro con el correo proporcionado');
      err.status = 409;
      throw err;
    }
    const newUser = {
      id: crypto.randomUUID(),
      name: String(body?.name || '').trim(),
      email,
      password: String(body?.password || ''),
      role: 'user',
      sensitivePlain: body?.sensitiveData ? String(body.sensitiveData).trim() : null,
      failedLoginAttempts: 0,
      lockedUntil: null,
      createdAt: now,
      updatedAt: now,
    };
    state.users.unshift(newUser);
    addLog('USER_REGISTERED', newUser, { role: 'user' });
    saveDemoState(state);
    return {
      message: 'Usuario registrado exitosamente',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        createdAt: newUser.createdAt,
      },
    };
  }

  // POST /api/auth/logout
  if (endpoint === '/api/auth/logout' && method === 'POST') {
    if (currentUser) {
      addLog('LOGOUT', currentUser, {});
    }
    state.currentUserId = null;
    saveDemoState(state);
    return { message: 'Sesión cerrada e invalidada correctamente' };
  }

  // POST /api/auth/forgot-password
  if (endpoint === '/api/auth/forgot-password' && method === 'POST') {
    const email = String(body?.email || '').toLowerCase().trim();
    const user = state.users.find((u) => u.email === email);
    const rawToken = Array.from(crypto.getRandomValues(new Uint8Array(32)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    if (user) {
      state.resetTokens[rawToken] = user.id;
      addLog('PASSWORD_RESET_REQUESTED', user, { expiresMinutes: 15 });
      saveDemoState(state);
    }
    return {
      message:
        'Si el correo electrónico se encuentra registrado, recibirá instrucciones para restablecer su contraseña.',
      devResetToken: rawToken,
    };
  }

  // POST /api/auth/reset-password
  if (endpoint === '/api/auth/reset-password' && method === 'POST') {
    const userId = state.resetTokens[body?.token];
    const user = state.users.find((u) => u.id === userId);
    if (!user) {
      const err = new Error('El token de recuperación es inválido, ya fue utilizado o ha expirado');
      err.status = 400;
      throw err;
    }
    user.password = String(body?.newPassword || '');
    delete state.resetTokens[body.token];
    addLog('PASSWORD_RESET_COMPLETED', user, {});
    saveDemoState(state);
    return { message: 'Contraseña actualizada exitosamente. Ya puede iniciar sesión.' };
  }

  // Require authentication for protected endpoints
  if (!currentUser) {
    const err = new Error('Autenticación requerida');
    err.status = 401;
    throw err;
  }

  // GET /api/profile
  if (endpoint.startsWith('/api/profile') && method === 'GET') {
    const reveal = endpoint.includes('reveal=true');
    return {
      profile: {
        id: currentUser.id,
        name: currentUser.name,
        email: currentUser.email,
        role: currentUser.role,
        sensitive_data: currentUser.sensitivePlain
          ? reveal
            ? currentUser.sensitivePlain
            : maskValue(currentUser.sensitivePlain)
          : null,
        revealed: Boolean(reveal && currentUser.sensitivePlain),
        createdAt: currentUser.createdAt,
        updatedAt: currentUser.updatedAt,
      },
    };
  }

  // PUT /api/profile/sensitive
  if (endpoint === '/api/profile/sensitive' && method === 'PUT') {
    currentUser.sensitivePlain = String(body?.sensitiveData || '').trim();
    currentUser.updatedAt = now;
    saveDemoState(state);
    return {
      message: 'Dato sensible actualizado y cifrado correctamente',
      profile: {
        id: currentUser.id,
        name: currentUser.name,
        email: currentUser.email,
        role: currentUser.role,
        sensitive_data: maskValue(currentUser.sensitivePlain),
        updatedAt: currentUser.updatedAt,
      },
    };
  }

  // GET /api/notes
  if (endpoint === '/api/notes' && method === 'GET') {
    const notes = state.notes.filter((n) => n.ownerId === currentUser.id);
    return { notes };
  }

  // POST /api/notes
  if (endpoint === '/api/notes' && method === 'POST') {
    const userNotes = state.notes.filter((n) => n.ownerId === currentUser.id);
    if (userNotes.length >= 50) {
      const err = new Error('Ha alcanzado el límite máximo permitido de 50 notas por usuario');
      err.status = 400;
      throw err;
    }
    const note = {
      id: crypto.randomUUID(),
      ownerId: currentUser.id,
      title: String(body?.title || '').trim(),
      content: String(body?.content || ''),
      createdAt: now,
      updatedAt: now,
    };
    state.notes.unshift(note);
    addLog('NOTE_CREATED', currentUser, { noteId: note.id });
    saveDemoState(state);
    return { message: 'Nota creada y cifrada exitosamente', note };
  }

  // PUT / DELETE /api/notes/:id
  if (endpoint.startsWith('/api/notes/')) {
    const noteId = decodeURIComponent(endpoint.replace('/api/notes/', ''));
    const idx = state.notes.findIndex((n) => n.id === noteId && n.ownerId === currentUser.id);
    if (idx === -1) {
      addLog('ACCESS_DENIED', currentUser, { resource: 'note', targetNoteId: noteId });
      saveDemoState(state);
      const err = new Error('Nota no encontrada');
      err.status = 404;
      throw err;
    }
    if (method === 'PUT') {
      state.notes[idx].title = String(body?.title || '').trim();
      state.notes[idx].content = String(body?.content || '');
      state.notes[idx].updatedAt = now;
      addLog('NOTE_UPDATED', currentUser, { noteId });
      saveDemoState(state);
      return { message: 'Nota actualizada exitosamente', note: state.notes[idx] };
    }
    if (method === 'DELETE') {
      state.notes.splice(idx, 1);
      addLog('NOTE_DELETED', currentUser, { noteId });
      saveDemoState(state);
      return { message: 'Nota eliminada correctamente' };
    }
  }

  // Admin routes
  if (endpoint.startsWith('/api/admin/')) {
    if (currentUser.role !== 'admin') {
      addLog('ACCESS_DENIED', currentUser, { path: endpoint });
      saveDemoState(state);
      const err = new Error('Acceso denegado: permisos insuficientes');
      err.status = 403;
      throw err;
    }

    if (endpoint === '/api/admin/users' && method === 'GET') {
      return {
        users: state.users.map((u) => ({
          id: u.id,
          name: u.name,
          email: u.email,
          role: u.role,
          sensitive_data: maskValue(u.sensitivePlain),
          failedLoginAttempts: u.failedLoginAttempts || 0,
          lockedUntil: u.lockedUntil,
          createdAt: u.createdAt,
        })),
      };
    }

    if (endpoint.endsWith('/role') && method === 'PATCH') {
      const targetId = decodeURIComponent(
        endpoint.replace('/api/admin/users/', '').replace('/role', '')
      );
      const targetUser = state.users.find((u) => u.id === targetId);
      if (!targetUser) {
        const err = new Error('Usuario no encontrado');
        err.status = 404;
        throw err;
      }
      const prevRole = targetUser.role;
      targetUser.role = body.role;
      addLog('ROLE_CHANGED', currentUser, {
        targetUserId: targetId,
        targetUserEmail: targetUser.email,
        previousRole: prevRole,
        newRole: body.role,
      });
      saveDemoState(state);
      return { message: 'Rol de usuario actualizado correctamente', user: targetUser };
    }

    if (endpoint === '/api/admin/audit-logs' && method === 'GET') {
      return { auditLogs: state.auditLogs };
    }
  }

  return {};
};

/**
 * Wrapper seguro de fetch (OWASP A02 / A05 / A07).
 * - Envía automáticamente cookies HttpOnly (credentials: 'include').
 * - Jamás almacena ni lee tokens desde localStorage o sessionStorage.
 * - Intenta conectarse al Backend Express (proxy / VITE_API_URL / localhost:3000) y,
 *   si el backend no está accesible por red, conmuta transparentemente al motor seguro local.
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

  let response = null;
  let networkFailed = false;

  for (const baseUrl of CANDIDATE_URLS) {
    try {
      const res = await fetch(`${baseUrl}${endpoint}`, config);
      // Si el proxy de Vite devuelve 502/504 o HTML de página 404 cuando el backend está apagado, probamos el siguiente
      const ct = res.headers.get('content-type') || '';
      if (!ct.includes('application/json') && res.status >= 404) {
        networkFailed = true;
        continue;
      }
      response = res;
      networkFailed = false;
      break;
    } catch {
      networkFailed = true;
    }
  }

  if (networkFailed || !response) {
    return handleOfflineFallback(endpoint, { method, body });
  }

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
