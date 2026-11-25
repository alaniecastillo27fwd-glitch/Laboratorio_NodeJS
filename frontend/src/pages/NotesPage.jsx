import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api.js';

export const NotesPage = () => {
  const [notes, setNotes] = useState([]);
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [errorMsg, setErrorMsg] = useState('');
  const [statusMsg, setStatusMsg] = useState('');
  const [loading, setLoading] = useState(true);

  const loadNotes = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.listNotes();
      setNotes(data.notes || []);
    } catch (err) {
      setErrorMsg(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadNotes();
  }, [loadNotes]);

  const resetForm = () => {
    setTitle('');
    setContent('');
    setEditingId(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMsg('');
    setStatusMsg('');

    try {
      if (editingId) {
        await api.updateNote(editingId, { title, content });
        setStatusMsg('Nota actualizada y recifrada (AES-256-GCM) correctamente.');
      } else {
        await api.createNote({ title, content });
        setStatusMsg('Nota creada y cifrada (AES-256-GCM) correctamente.');
      }
      resetForm();
      await loadNotes();
    } catch (err) {
      setErrorMsg(err.message);
    }
  };

  const handleStartEdit = (note) => {
    setEditingId(note.id);
    setTitle(note.title);
    setContent(note.content);
    setErrorMsg('');
    setStatusMsg('');
  };

  const handleDelete = async (id) => {
    setErrorMsg('');
    setStatusMsg('');
    try {
      await api.deleteNote(id);
      if (editingId === id) {
        resetForm();
      }
      setStatusMsg('Nota eliminada correctamente.');
      await loadNotes();
    } catch (err) {
      setErrorMsg(err.message);
    }
  };

  return (
    <div className="grid-two">
      <section className="card">
        <h2>{editingId ? 'Editar Nota Privada' : 'Nueva Nota Privada'} (RF-04)</h2>
        <p className="muted">
          El contenido se cifra en el servidor con <strong>AES-256-GCM</strong> (IV aleatorio de 12B
          + AuthTag de 16B). Cuota: {notes.length} / 50 notas.
        </p>

        {errorMsg && <div className="alert alert-error">{errorMsg}</div>}
        {statusMsg && <div className="alert alert-success">{statusMsg}</div>}

        <form onSubmit={handleSubmit} className="form">
          <label htmlFor="note-title">Título (máx. 120 caracteres)</label>
          <input
            id="note-title"
            type="text"
            required
            maxLength={120}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />

          <label htmlFor="note-content">Contenido confidencial (máx. 5,000 caracteres)</label>
          <textarea
            id="note-content"
            rows={6}
            required
            maxLength={5000}
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />

          <div className="btn-row">
            <button type="submit" className="btn btn-primary">
              {editingId ? 'Guardar Cambios' : 'Crear Nota Cifrada'}
            </button>
            {editingId && (
              <button type="button" className="btn btn-secondary" onClick={resetForm}>
                Cancelar
              </button>
            )}
          </div>
        </form>
      </section>

      <section className="card">
        <h2>Mis Notas ({notes.length})</h2>
        {loading ? (
          <p className="muted">Descifrando notas...</p>
        ) : notes.length === 0 ? (
          <p className="muted">Aún no tiene notas registradas.</p>
        ) : (
          <div className="notes-list">
            {notes.map((note) => (
              <article key={note.id} className="note-item">
                <div className="note-header">
                  <h3>{note.title}</h3>
                  <small className="muted">ID: {note.id}</small>
                </div>
                <p className="note-body">{note.content}</p>
                <div className="btn-row">
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleStartEdit(note)}
                  >
                    Editar
                  </button>
                  <button
                    type="button"
                    className="btn btn-danger btn-sm"
                    onClick={() => handleDelete(note.id)}
                  >
                    Eliminar
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
};
