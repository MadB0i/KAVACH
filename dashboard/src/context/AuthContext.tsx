import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import { setAuthToken as setApiToken, clearAuthToken as clearApiToken, getStatus } from '../api';

interface AuthContextValue {
  token: string | null;
  isAuthenticated: boolean;
  actor: string | null;
  login: (token: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

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

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
