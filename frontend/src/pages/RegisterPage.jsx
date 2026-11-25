import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../services/api.js';

export const RegisterPage = () => {
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [sensitiveData, setSensitiveData] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [details, setDetails] = useState([]);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setDetails([]);
    setSubmitting(true);

    try {
      const payload = {
        name,
        email,
        password,
        ...(sensitiveData.trim() && { sensitiveData: sensitiveData.trim() }),
      };
      await api.register(payload);
      navigate('/login');
    } catch (err) {
      setErrorMsg(err.message || 'No se pudo completar el registro');
      setDetails(err.details || []);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <section className="card auth-card">
      <h1>Registro de Usuario (RF-01)</h1>
      <p className="muted">La contraseña se almacena exclusivamente como hash Argon2id.</p>

      {errorMsg && (
        <div className="alert alert-error" role="alert">
          <p>{errorMsg}</p>
          {details.length > 0 && (
            <ul>
              {details.map((d, idx) => (
                <li key={idx}>{d.message}</li>
              ))}
            </ul>
          )}
        </div>
      )}

      <form onSubmit={handleSubmit} className="form">
        <label htmlFor="reg-name">Nombre completo</label>
        <input
          id="reg-name"
          type="text"
          required
          minLength={2}
          maxLength={100}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />

        <label htmlFor="reg-email">Correo electrónico</label>
        <input
          id="reg-email"
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <label htmlFor="reg-password">Contraseña</label>
        <input
          id="reg-password"
          type="password"
          required
          minLength={10}
          maxLength={72}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <small className="hint">
          Política: Mínimo 10 caracteres, al menos 1 mayúscula, 1 minúscula, 1 número y 1 símbolo.
        </small>

        <label htmlFor="reg-sensitive">
          Teléfono o Documento (Opcional — se cifra con AES-256-GCM)
        </label>
        <input
          id="reg-sensitive"
          type="text"
          maxLength={64}
          placeholder="Ej. 555-123-4567"
          value={sensitiveData}
          onChange={(e) => setSensitiveData(e.target.value)}
        />

        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? 'Registrando...' : 'Crear Cuenta'}
        </button>
      </form>

      <div className="auth-footer">
        <Link to="/login">¿Ya tiene cuenta? Iniciar sesión</Link>
      </div>
    </section>
  );
};
