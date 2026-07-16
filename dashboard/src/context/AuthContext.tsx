import { useState, useCallback, useEffect, type ReactNode } from 'react';
import { setAuthToken as setApiToken, clearAuthToken as clearApiToken, getStatus } from '../api';
import { AuthContext } from './useAuth';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [actor, setActor] = useState<string | null>(null);
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    const stored = sessionStorage.getItem('kavach_token');
    if (stored) {
      setToken(stored);
      setApiToken(stored);
      getStatus()
        .then((status) => {
          setActor(status.service || 'admin');
          setInitialized(true);
        })
        .catch(() => {
          setToken(null);
          clearApiToken();
          sessionStorage.removeItem('kavach_token');
          setInitialized(true);
        });
    } else {
      setInitialized(true);
    }
  }, []);

  const login = useCallback(async (newToken: string) => {
    setApiToken(newToken);
    const status = await getStatus();
    setToken(newToken);
    setActor(status.service || 'admin');
    sessionStorage.setItem('kavach_token', newToken);
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setActor(null);
    clearApiToken();
    sessionStorage.removeItem('kavach_token');
  }, []);

  if (!initialized) {
    return null;
  }

  return (
    <AuthContext.Provider value={{ token, isAuthenticated: token !== null, actor, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
