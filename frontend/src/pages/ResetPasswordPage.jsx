import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api.js';

export const ResetPasswordPage = () => {
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [devTokenNotice, setDevTokenNotice] = useState('');
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRequestToken = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setStatusMsg('');
    setDevTokenNotice('');
    setLoading(true);

    try {
      const res = await api.forgotPassword({ email });
      setStatusMsg(res.message);
      if (res.devResetToken) {
        setDevTokenNotice(res.devResetToken);
        setToken(res.devResetToken);
      }
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setStatusMsg('');
    setLoading(true);

    try {
      const res = await api.resetPassword({ token: token.trim(), newPassword });
      setStatusMsg(res.message);
      setToken('');
      setNewPassword('');
      setDevTokenNotice('');
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid-two">
      <section className="card">
        <h2>1. Solicitar Token de Recuperación (RF-06)</h2>
        <p className="muted">
          Se genera un token de 32 bytes con <code>crypto.randomBytes(32)</code> y en la BD solo se
          almacena su hash SHA-256.
        </p>

        <form onSubmit={handleRequestToken} className="form">
          <label htmlFor="forgot-email">Correo de la cuenta</label>
          <input
            id="forgot-email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <button type="submit" className="btn btn-secondary" disabled={loading}>
            Generar Token (15 min)
          </button>
        </form>

        {devTokenNotice && (
          <div className="alert alert-info">
            <strong>Token de prueba (Solo visible en entorno dev):</strong>
            <code className="code-block">{devTokenNotice}</code>
          </div>
        )}
      </section>

      <section className="card">
        <h2>2. Restablecer Contraseña</h2>
        {statusMsg && <div className="alert alert-success">{statusMsg}</div>}
        {errorMsg && <div className="alert alert-error">{errorMsg}</div>}

        <form onSubmit={handleResetPassword} className="form">
          <label htmlFor="reset-token">Token de recuperación (64 caracteres hex)</label>
          <input
            id="reset-token"
            type="text"
            required
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />

          <label htmlFor="reset-new-password">Nueva Contraseña</label>
          <input
            id="reset-new-password"
            type="password"
            required
            minLength={10}
            maxLength={72}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <small className="hint">
            Mín. 10 caracteres, mayúscula, minúscula, número y símbolo.
          </small>

          <button type="submit" className="btn btn-primary" disabled={loading}>
            Actualizar Contraseña
          </button>
        </form>

        <div className="auth-footer">
          <Link to="/login">Volver a Iniciar Sesión</Link>
        </div>
      </section>
    </div>
  );
};
