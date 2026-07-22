import { useState, useCallback, useEffect, type ReactNode } from 'react';
import {
  setAuthToken as setApiToken,
  clearAuthToken as clearApiToken,
  getStatus,
} from '../api';
import { AuthContext } from './useAuth';

const AUTH_INVALIDATED_EVENT = 'kavach:auth-invalidated';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [actor, setActor] = useState<string | null>(null);

  const login = useCallback(async (newToken: string) => {
    setApiToken(newToken);
    try {
      await getStatus();
      setToken(newToken);
      setActor('local-operator');
    } catch (error) {
      clearApiToken();
      setToken(null);
      setActor(null);
      throw error;
    }
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setActor(null);
    clearApiToken();
  }, []);

  useEffect(() => {
    window.addEventListener(AUTH_INVALIDATED_EVENT, logout);
    return () => window.removeEventListener(AUTH_INVALIDATED_EVENT, logout);
  }, [logout]);

  return (
    <AuthContext.Provider value={{ token, isAuthenticated: token !== null, actor, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
