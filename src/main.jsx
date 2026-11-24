import React from 'react';
import { createRoot } from 'react-dom/client';

function App() {
  return (
    <main>
      <h1>RepoGuard</h1>
      <p>AI-powered code review and security analysis</p>
    </main>
  );
}

const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Required React mount element #root was not found.');
}

createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
