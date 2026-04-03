import { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle, AlertCircle, Info, X } from 'lucide-react';

const ToastContext = createContext();

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback(({ title, message, type = 'info', duration = 5000 }) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, title, message, type, duration }]);
    if (duration > 0) {
      setTimeout(() => removeToast(id), duration);
    }
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const success = (title, message) => addToast({ title, message, type: 'success' });
  const error = (title, message) => addToast({ title, message, type: 'error' });
  const info = (title, message) => addToast({ title, message, type: 'info' });
  const warning = (title, message) => addToast({ title, message, type: 'warning' });

  return (
    <ToastContext.Provider value={{ success, error, info, warning, removeToast }}>
      {children}
      <div className="toast-container">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.type}`}>
            <div className="toast-icon">
              {toast.type === 'success' && <CheckCircle size={20} className="text-green" />}
              {toast.type === 'error' && <AlertCircle size={20} className="text-red" />}
              {toast.type === 'warning' && <AlertCircle size={20} className="text-amber" />}
              {toast.type === 'info' && <Info size={20} className="text-accent" />}
            </div>
            <div style={{ flex: 1 }}>
              {toast.title && <div className="toast-title">{toast.title}</div>}
              {toast.message && <div className="toast-body">{toast.message}</div>}
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => {
  const context = useContext(ToastContext);
  if (!context) throw new Error('useToast must be used within ToastProvider');
  return context;
};
