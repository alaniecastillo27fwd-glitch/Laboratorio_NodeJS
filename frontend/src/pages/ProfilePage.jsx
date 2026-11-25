import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api.js';

export const ProfilePage = () => {
  const [profile, setProfile] = useState(null);
  const [revealed, setRevealed] = useState(false);
  const [newSensitiveData, setNewSensitiveData] = useState('');
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [loading, setLoading] = useState(true);

  const fetchProfile = useCallback(async (shouldReveal) => {
    setLoading(true);
    setErrorMsg('');
    try {
      const data = await api.getProfile(shouldReveal);
      setProfile(data.profile);
      setRevealed(Boolean(data.profile?.revealed));
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchProfile(false);
  }, [fetchProfile]);

  const handleToggleReveal = () => {
    fetchProfile(!revealed);
  };

  const handleUpdateSensitive = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setStatusMsg('');
    try {
      await api.updateSensitiveData(newSensitiveData);
      setNewSensitiveData('');
      setStatusMsg('Dato sensible cifrado con AES-256-GCM y almacenado correctamente.');
      await fetchProfile(false);
    } catch (err) {
      setErrorMsg(err.message);
    }
  };

  return (
    <div className="grid-two">
      <section className="card">
        <h2>Mi Perfil de Seguridad (RF-05)</h2>
        {loading && !profile ? (
          <p className="muted">Cargando perfil...</p>
        ) : profile ? (
          <div className="profile-details">
            <p>
              <strong>ID (UUID):</strong> <code>{profile.id}</code>
            </p>
            <p>
              <strong>Nombre:</strong> {profile.name}
            </p>
            <p>
              <strong>Correo:</strong> {profile.email}
            </p>
            <p>
              <strong>Rol verificado en servidor:</strong>{' '}
              <span className="badge">{profile.role}</span>
            </p>
            <div className="sensitive-box">
              <p>
                <strong>Dato Sensible (Teléfono / Documento):</strong>{' '}
                <code>{profile.sensitive_data || 'No registrado'}</code>
              </p>
              {profile.sensitive_data && (
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleToggleReveal}
                >
                  {revealed ? 'Ocultar (***-***-1234)' : 'Revelar Dato Completo'}
                </button>
              )}
            </div>
          </div>
        ) : null}
      </section>

      <section className="card">
        <h2>Actualizar Dato Sensible (AES-256-GCM)</h2>
        <p className="muted">
          Se almacena cifrado en la columna <code>sensitive_data_enc</code> y se muestra enmascarado
          por defecto.
        </p>

        {errorMsg && <div className="alert alert-error">{errorMsg}</div>}
        {statusMsg && <div className="alert alert-success">{statusMsg}</div>}

        <form onSubmit={handleUpdateSensitive} className="form">
          <label htmlFor="sensitive-input">Teléfono o Número de Documento (4 a 64 chars)</label>
          <input
            id="sensitive-input"
            type="text"
            required
            minLength={4}
            maxLength={64}
            placeholder="Ej. 506-8888-1234"
            value={newSensitiveData}
            onChange={(e) => setNewSensitiveData(e.target.value)}
          />
          <button type="submit" className="btn btn-primary">
            Cifrar y Guardar
          </button>
        </form>
      </section>
    </div>
  );
};
