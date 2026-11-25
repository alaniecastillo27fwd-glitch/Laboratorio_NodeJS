import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

export const Navbar = () => {
  const { user, logoutUser } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logoutUser();
    navigate('/login');
  };

  return (
    <header className="navbar">
      <div className="navbar-inner">
        <Link to={user ? '/notes' : '/login'} className="brand">
          SecureVault
        </Link>

        <nav className="nav-links">
          {user ? (
            <>
              <Link to="/notes">Mis Notas</Link>
              <Link to="/profile">Mi Perfil</Link>
              {user.role === 'admin' && <Link to="/admin">Panel Admin</Link>}
              <span className="user-badge">
                {user.email} ({user.role})
              </span>
              <button type="button" onClick={handleLogout} className="btn btn-secondary btn-sm">
                Cerrar Sesión
              </button>
            </>
          ) : (
            <>
              <Link to="/login">Iniciar Sesión</Link>
              <Link to="/register">Registrarse</Link>
              <Link to="/reset-password">Recuperar Contraseña</Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
};
