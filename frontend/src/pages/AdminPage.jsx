import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api.js';
import { useAuth } from '../context/AuthContext.jsx';

export const AdminPage = () => {
  const { user: currentUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [errorMsg, setErrorMsg] = useState('');
  const [statusMsg, setStatusMsg] = useState('');
  const [loading, setLoading] = useState(true);

  const loadAdminData = useCallback(async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const [usersRes, logsRes] = await Promise.all([api.listUsers(), api.listAuditLogs()]);
      setUsers(usersRes.users || []);
      setAuditLogs(logsRes.auditLogs || []);
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAdminData();
  }, [loadAdminData]);

  const handleRoleChange = async (targetUserId, newRole) => {
    setErrorMsg('');
    setStatusMsg('');
    try {
      await api.changeUserRole(targetUserId, newRole);
      setStatusMsg(`Rol actualizado a '${newRole}' y registrado en la bitácora de auditoría.`);
      await loadAdminData();
    } catch (err) {
      setErrorMsg(err.message);
    }
  };

  return (
    <div className="stack">
      <section className="card">
        <div className="section-header">
          <h2>Panel de Administración — Gestión de Usuarios (RF-07)</h2>
          <button type="button" className="btn btn-secondary btn-sm" onClick={loadAdminData}>
            Refrescar Datos
          </button>
        </div>

        {errorMsg && <div className="alert alert-error">{errorMsg}</div>}
        {statusMsg && <div className="alert alert-success">{statusMsg}</div>}

        {loading ? (
          <p className="muted">Cargando usuarios...</p>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Nombre</th>
                  <th>Correo</th>
                  <th>Rol Actual</th>
                  <th>Dato Sensible (Enmascarado)</th>
                  <th>Fallos Login</th>
                  <th>Acción de Rol</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.name}</td>
                    <td>{u.email}</td>
                    <td>
                      <span className="badge">{u.role}</span>
                    </td>
                    <td>
                      <code>{u.sensitive_data || 'N/A'}</code>
                    </td>
                    <td>{u.failedLoginAttempts}</td>
                    <td>
                      <select
                        value={u.role}
                        disabled={u.id === currentUser?.id}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                      >
                        <option value="user">user</option>
                        <option value="admin">admin</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Bitácora de Eventos de Seguridad (OWASP A09 / RF-07)</h2>
        <p className="muted">
          Últimos 100 eventos (logins fallidos, bloqueos por fuerza bruta, cambios de rol y accesos
          denegados IDOR/RBAC). Sin contraseñas ni tokens.
        </p>

        {loading ? (
          <p className="muted">Cargando bitácora...</p>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Fecha (UTC)</th>
                  <th>Evento</th>
                  <th>Usuario</th>
                  <th>IP</th>
                  <th>Detalles (JSON Sanitizado)</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log) => (
                  <tr key={log.id}>
                    <td>{new Date(log.created_at).toLocaleString()}</td>
                    <td>
                      <code>{log.event_type}</code>
                    </td>
                    <td>{log.user_email || log.user_id || 'Anónimo'}</td>
                    <td>
                      <code>{log.ip_address}</code>
                    </td>
                    <td>
                      <code className="json-cell">{JSON.stringify(log.details)}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
};
