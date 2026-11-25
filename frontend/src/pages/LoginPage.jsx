import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

export const LoginPage = () => {
  const { loginUser } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [isRateLimited, setIsRateLimited] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const performLogin = async (loginEmail, loginPassword, redirectTo = '/notes') => {
    setErrorMsg('');
    setIsRateLimited(false);
    setSubmitting(true);

    try {
      await loginUser({ email: loginEmail, password: loginPassword });
      navigate(redirectTo);
    } catch (err) {
      if (err.status === 429) {
        setIsRateLimited(true);
      }
      setErrorMsg(
        err.message === 'Failed to fetch'
          ? 'No se pudo conectar con el servidor Backend (http://localhost:3000). Verifique que el backend esté en ejecución.'
          : err.message || 'Credenciales inválidas'
      );
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    await performLogin(email, password, '/notes');
  };

  const handleQuickAdminLogin = async () => {
    const adminEmail = 'admin@securevault.com';
    const adminPass = 'AdminSecure2025!';
    setEmail(adminEmail);
    setPassword(adminPass);
    await performLogin(adminEmail, adminPass, '/admin');
  };

  const handleQuickUserLogin = async () => {
    const userEmail = 'usuario@securevault.com';
    const userPass = 'UserSecure2025!';
    setEmail(userEmail);
    setPassword(userPass);
    await performLogin(userEmail, userPass, '/notes');
  };

  return (
    <section className="card auth-card">
      <h1>Iniciar Sesión</h1>
      <p className="muted">Acceso seguro mediante cookie HttpOnly (OWASP A07)</p>

      {errorMsg && (
        <div className={`alert ${isRateLimited ? 'alert-warning' : 'alert-error'}`} role="alert">
          <strong>{isRateLimited ? 'Bloqueo Temporal (HTTP 429): ' : 'Error: '}</strong>
          {errorMsg}
        </div>
      )}

      <form onSubmit={handleSubmit} className="form">
        <label htmlFor="login-email">Correo electrónico</label>
        <input
          id="login-email"
          type="email"
          required
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={submitting}
        />

        <label htmlFor="login-password">Contraseña</label>
        <input
          id="login-password"
          type="password"
          required
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={submitting}
        />

        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? 'Verificando...' : 'Entrar'}
        </button>
      </form>

      <div className="quick-access-box">
        <p className="muted">
          <strong>Acceso Rápido para Evaluación / Demo (RF-03 y RF-07):</strong>
        </p>
        <div className="btn-row">
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handleQuickAdminLogin}
            disabled={submitting}
          >
            Entrar como Administrador (admin)
          </button>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={handleQuickUserLogin}
            disabled={submitting}
          >
            Entrar como Usuario (user)
          </button>
        </div>
      </div>

      <div className="auth-footer">
        <Link to="/reset-password">¿Olvidó su contraseña?</Link>
        <span> | </span>
        <Link to="/register">Crear una cuenta</Link>
      </div>
    </section>
  );
};
