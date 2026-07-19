import { useState, useCallback, useEffect, type ReactNode } from 'react';
import { setAuthToken as setApiToken, clearAuthToken as clearApiToken, getStatus } from '../api';
import { AuthContext } from './useAuth';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [actor, setActor] = useState<string | null>(null);

  const login = useCallback(async (newToken: string, actorId = 'dashboard-operator') => {
    setApiToken(newToken);
    await getStatus();
    setToken(newToken);
    setActor(actorId.trim() || 'dashboard-operator');
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setActor(null);
    clearApiToken();
  }, []);

  useEffect(() => {
    window.addEventListener('kavach:unauthorized', logout);
    return () => window.removeEventListener('kavach:unauthorized', logout);
  }, [logout]);

  return (
    <AuthContext.Provider value={{ token, isAuthenticated: token !== null, actor, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
