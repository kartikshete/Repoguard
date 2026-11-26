import { useEffect, useState } from 'react';

function isSafeGitHubUrl(value) {
  if (typeof value !== 'string') {
    return false;
  }

  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      url.hostname === 'github.com' &&
      !url.username &&
      !url.password &&
      !url.port &&
      !url.search &&
      !url.hash
    );
  } catch {
    return false;
  }
}

function isRepositorySummary(repository) {
  return (
    repository &&
    typeof repository === 'object' &&
    !Array.isArray(repository) &&
    Number.isSafeInteger(repository.id) &&
    typeof repository.name === 'string' &&
    typeof repository.fullName === 'string' &&
    (typeof repository.description === 'string' ||
      repository.description === null) &&
    (typeof repository.language === 'string' || repository.language === null) &&
    (typeof repository.defaultBranch === 'string' ||
      repository.defaultBranch === null) &&
    (typeof repository.updatedAt === 'string' || repository.updatedAt === null) &&
    typeof repository.archived === 'boolean' &&
    typeof repository.fork === 'boolean' &&
    isSafeGitHubUrl(repository.htmlUrl)
  );
}

function formatUpdatedAt(value) {
  const timestamp = Date.parse(value);

  if (!Number.isFinite(timestamp)) {
    return null;
  }

  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(
    timestamp,
  );
}

export default function App() {
  const [sessionState, setSessionState] = useState('loading');
  const [user, setUser] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const [isSigningOut, setIsSigningOut] = useState(false);
  const [repositories, setRepositories] = useState([]);
  const [repositoryState, setRepositoryState] = useState('idle');
  const [repositoryError, setRepositoryError] = useState('');
  const [hasMoreRepositories, setHasMoreRepositories] = useState(false);
  const [repositoryAttempt, setRepositoryAttempt] = useState(0);

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

  useEffect(() => {
    if (sessionState !== 'signed-in' || !user) {
      return undefined;
    }

    const controller = new AbortController();

    async function loadRepositories() {
      setRepositoryState('loading');
      setRepositoryError('');

      try {
        const response = await fetch('/api/repositories', {
          credentials: 'include',
          signal: controller.signal,
        });

        if (response.status === 401) {
          setUser(null);
          setSessionState('signed-out');
          setRepositories([]);
          setRepositoryState('idle');
          return;
        }

        if (!response.ok) {
          throw new Error('The repository request failed.');
        }

        const payload = await response.json();

        if (
          !Array.isArray(payload.repositories) ||
          typeof payload.hasMore !== 'boolean' ||
          !payload.repositories.every(isRepositorySummary)
        ) {
          throw new Error('The repository response was invalid.');
        }

        setRepositories(payload.repositories);
        setHasMoreRepositories(payload.hasMore);
        setRepositoryState('loaded');
      } catch {
        if (controller.signal.aborted) {
          return;
        }

        setRepositoryState('error');
        setRepositoryError(
          'Could not load public repositories. Check the API connection and try again.',
        );
      }
    }

    loadRepositories();

    return () => controller.abort();
  }, [repositoryAttempt, sessionState, user]);

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
            <section
              className="repository-section"
              aria-labelledby="repositories-title"
              aria-busy={repositoryState === 'loading'}
            >
              <h2 id="repositories-title">Public repositories</h2>
              {repositoryState === 'loading' ? (
                <p role="status">Loading your public repositories…</p>
              ) : repositoryState === 'error' ? (
                <>
                  <p className="app-feedback" role="alert">
                    {repositoryError}
                  </p>
                  <button
                    className="auth-button"
                    type="button"
                    onClick={() => setRepositoryAttempt((attempt) => attempt + 1)}
                  >
                    Try again
                  </button>
                </>
              ) : repositories.length === 0 ? (
                <p>No public repositories were found for this account.</p>
              ) : (
                <>
                  <ul className="repository-list">
                    {repositories.map((repository) => {
                      const updatedAt = formatUpdatedAt(repository.updatedAt);

                      return (
                        <li key={repository.id} className="repository-card">
                          <h3>
                            <a
                              href={repository.htmlUrl}
                              rel="noreferrer"
                              target="_blank"
                            >
                              {repository.fullName}
                            </a>
                          </h3>
                          {repository.description ? (
                            <p>{repository.description}</p>
                          ) : null}
                          <p>
                            {repository.language || 'Language not specified'}
                            {updatedAt ? ` · Updated ${updatedAt}` : ''}
                            {repository.archived ? ' · Archived' : ''}
                          </p>
                        </li>
                      );
                    })}
                  </ul>
                  {hasMoreRepositories ? (
                    <p>
                      More repositories are available. This list shows the 100
                      most recently updated public repositories.
                    </p>
                  ) : null}
                </>
              )}
            </section>
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
