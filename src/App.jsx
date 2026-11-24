export default function App() {
  return (
    <main className="app-shell">
      <header className="app-header">
        <p className="app-eyebrow">Repository intelligence</p>
        <h1>RepoGuard</h1>
        <p className="app-description">
          AI-powered code review and security analysis.
        </p>
      </header>

      <section className="welcome-panel" aria-labelledby="welcome-title">
        <h2 id="welcome-title">Review your repository with confidence</h2>
        <p>
          Connect a GitHub repository to start a code quality and security
          review.
        </p>
      </section>
    </main>
  );
}
