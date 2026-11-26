import { useEffect, useState } from 'react';

export default function App() {
  const [sessionState, setSessionState] = useState('loading');
  const [user, setUser] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [isSigningOut, setIsSigningOut] = useState(false);

  useEffect(() => {
    const controller = new AbortController();

    async function loadSession() {
      try {
        const response = await fetch('/api/auth/me', {
          credentials: 'include',
          signal: controller.signal,
        });

        if (response.status === 401) {
          setUser(null);
          setSessionState('signed-out');
          return;
        }

        if (!response.ok) {
          throw new Error('The session request failed.');
        }

        const payload = await response.json();

        if (!payload.user || typeof payload.user.username !== 'string') {
          throw new Error('The session response was invalid.');
        }

        setUser(payload.user);
        setSessionState('signed-in');
      } catch {
        if (controller.signal.aborted) {
          return;
        }

        setUser(null);
        setSessionState('error');
        setErrorMessage(
          'Could not load your RepoGuard session. Check that the API is available and try again.',
        );
      }
    }

    loadSession();

    return () => controller.abort();
  }, []);

  async function handleSignOut() {
    setIsSigningOut(true);
    setErrorMessage('');

    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('The logout request failed.');
      }

      setUser(null);
      setSessionState('signed-out');
    } catch {
      setErrorMessage('Could not sign out. Please try again.');
    } finally {
      setIsSigningOut(false);
    }
  }

  return (
    <main className="app-shell">
      <header className="app-header">
        <p className="app-eyebrow">Repository intelligence</p>
        <h1>RepoGuard</h1>
        <p className="app-description">
          AI-powered code review and security analysis.
        </p>
      </header>

      <section
        className="welcome-panel"
        aria-labelledby="welcome-title"
        aria-busy={sessionState === 'loading'}
      >
        {sessionState === 'loading' ? (
          <>
            <h2 id="welcome-title">Checking your session</h2>
            <p role="status">Checking your GitHub session…</p>
          </>
        ) : user ? (
          <>
            <h2 id="welcome-title">Welcome, {user.displayName || user.username}</h2>
            <div className="user-profile">
              {user.avatarUrl ? (
                <img
                  className="user-avatar"
                  src={user.avatarUrl}
                  alt=""
                  referrerPolicy="no-referrer"
                />
              ) : null}
              <p className="user-handle">@{user.username}</p>
            </div>
            <p>Your GitHub account is connected to RepoGuard.</p>
            <button
              className="auth-button"
              type="button"
              onClick={handleSignOut}
              disabled={isSigningOut}
            >
              {isSigningOut ? 'Signing out…' : 'Sign out'}
            </button>
          </>
        ) : (
          <>
            <h2 id="welcome-title">Connect your GitHub account</h2>
            <p>
              Sign in to access your RepoGuard workspace. Repository reviews
              will appear here when you add one.
            </p>
            <a className="auth-button" href="/api/auth/github">
              Continue with GitHub
            </a>
          </>
        )}

        {errorMessage ? (
          <p className="app-feedback" role="alert">
            {errorMessage}
          </p>
        ) : null}
      </section>
    </main>
  );
}
