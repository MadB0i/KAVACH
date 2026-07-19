import { useState, useCallback, type ReactNode } from 'react';
import { setAuthToken as setApiToken, clearAuthToken as clearApiToken, getStatus } from '../api';
import { AuthContext } from './useAuth';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [actor, setActor] = useState<string | null>(null);

  const login = useCallback(async (newToken: string) => {
    setApiToken(newToken);
    const status = await getStatus();
    setToken(newToken);
    setActor(status.service || 'operator');
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setActor(null);
    clearApiToken();
  }, []);

  return (
    <AuthContext.Provider value={{ token, isAuthenticated: token !== null, actor, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
