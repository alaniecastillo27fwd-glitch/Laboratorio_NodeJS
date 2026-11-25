import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

/**
 * Protege rutas autenticadas y valida el rol requerido (p. ej. requiredRole="admin").
 * La autorización real siempre se verifica además en el servidor Express (OWASP A01).
 */
export const ProtectedRoute = ({ children, requiredRole = null }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="container">
        <p className="muted">Verificando sesión segura...</p>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole && user.role !== requiredRole) {
    return <Navigate to="/notes" replace />;
  }

  return children;
};
