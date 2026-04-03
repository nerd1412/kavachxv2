import React from 'react';
import { AlertCircle, RefreshCcw } from 'lucide-react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Dashboard Crash:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ 
          height: '100vh', width: '100%', display: 'flex', flexDirection: 'column', 
          alignItems: 'center', justifyContent: 'center', background: 'var(--bg-main)',
          color: 'var(--text-main)', padding: 20, textAlign: 'center'
        }}>
          <AlertCircle size={48} color="var(--red)" style={{ marginBottom: 16 }} />
          <h2 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Interface Error</h2>
          <p style={{ color: 'var(--text-muted)', maxWidth: 400, marginBottom: 24 }}>
            Something went wrong while rendering this page. This could be due to a network timeout or a malformed data payload.
          </p>
          <button 
            onClick={() => window.location.reload()}
            style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px',
              background: 'var(--accent)', color: '#fff', border: 'none',
              borderRadius: 8, fontWeight: 600, cursor: 'pointer'
            }}
          >
            <RefreshCcw size={16} />
            Reload Interface
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
