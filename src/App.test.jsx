import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App.jsx';

const testRepository = {
  id: 42,
  name: 'repoguard',
  fullName: 'kartik/repoguard',
  description: 'Code review and security analysis',
  language: 'JavaScript',
  defaultBranch: 'main',
  updatedAt: '2026-11-26T12:00:00Z',
  archived: false,
  fork: false,
  htmlUrl: 'https://github.com/kartik/repoguard',
};

function createSessionResponse(user = { username: 'kartik' }) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ user }),
  };
}

function createRepositoryResponse(repositories = [], hasMore = false) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ repositories, hasMore }),
  };
}

beforeEach(() => {
  globalThis.fetch = jest.fn();
});

afterEach(() => {
  cleanup();
});

describe('App workspace', () => {
  test('shows a loading status while the session request is pending', () => {
    globalThis.fetch.mockReturnValue(new Promise(() => {}));

    render(<App />);

    expect(screen.getByRole('status').textContent).toBe(
      'Checking your GitHub session…',
    );
  });

  test('shows the GitHub sign-in link when there is no active session', async () => {
    globalThis.fetch.mockResolvedValue({ ok: false, status: 401 });

    render(<App />);

    expect(
      await screen.findByRole('heading', {
        name: 'Connect your GitHub account',
      }),
    ).toBeTruthy();
    expect(
      screen
        .getByRole('link', { name: 'Continue with GitHub' })
        .getAttribute('href'),
    ).toBe('/api/auth/github');
  });

  test('loads the public repository list after authentication', async () => {
    globalThis.fetch
      .mockResolvedValueOnce(createSessionResponse())
      .mockReturnValueOnce(new Promise(() => {}));

    render(<App />);

    expect(
      await screen.findByRole('heading', { name: 'Welcome, kartik' }),
    ).toBeTruthy();
    expect(
      await screen.findByText('Loading your public repositories…'),
    ).toBeTruthy();
    expect(globalThis.fetch).toHaveBeenNthCalledWith(
      2,
      '/api/repositories',
      expect.objectContaining({ credentials: 'include' }),
    );
  });

  test('shows the authenticated profile and signs out successfully', async () => {
    globalThis.fetch
      .mockResolvedValueOnce(
        createSessionResponse({
          username: 'kartik',
          displayName: 'Kartik Shete',
        }),
      )
      .mockResolvedValueOnce(createRepositoryResponse([testRepository], true))
      .mockResolvedValueOnce({ ok: true, status: 204 });

    const user = userEvent.setup();
    render(<App />);

    expect(
      await screen.findByRole('heading', { name: 'Welcome, Kartik Shete' }),
    ).toBeTruthy();
    expect(screen.getByText('@kartik')).toBeTruthy();
    expect(
      await screen.findByRole('link', { name: 'kartik/repoguard' }),
    ).toBeTruthy();
    expect(
      screen.getByText(/100 most recently updated public repositories/),
    ).toBeTruthy();

    await user.click(await screen.findByRole('button', { name: 'Sign out' }));

    expect(
      await screen.findByRole('link', { name: 'Continue with GitHub' }),
    ).toBeTruthy();
    expect(globalThis.fetch).toHaveBeenNthCalledWith(3, '/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
    });
  });

  test('shows an empty state when no public repositories are returned', async () => {
    globalThis.fetch
      .mockResolvedValueOnce(createSessionResponse())
      .mockResolvedValueOnce(createRepositoryResponse());

    render(<App />);

    expect(
      await screen.findByText(
        'No public repositories were found for this account.',
      ),
    ).toBeTruthy();
  });

  test('offers a retry after the repository request fails', async () => {
    globalThis.fetch
      .mockResolvedValueOnce(createSessionResponse())
      .mockResolvedValueOnce({ ok: false, status: 502 })
      .mockResolvedValueOnce(createRepositoryResponse([testRepository]));

    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      'Could not load public repositories. Check the API connection and try again.',
    );

    await user.click(screen.getByRole('button', { name: 'Try again' }));

    expect(
      await screen.findByRole('link', { name: 'kartik/repoguard' }),
    ).toBeTruthy();
  });

  test('does not render an unsafe repository URL', async () => {
    const unsafeRepository = {
      ...testRepository,
      htmlUrl: 'javascript:alert(1)',
    };
    globalThis.fetch
      .mockResolvedValueOnce(createSessionResponse())
      .mockResolvedValueOnce(createRepositoryResponse([unsafeRepository]));

    render(<App />);

    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      'Could not load public repositories. Check the API connection and try again.',
    );
    expect(screen.queryByRole('link', { name: 'kartik/repoguard' })).toBeNull();
  });

  test('shows a safe message when the session request fails', async () => {
    globalThis.fetch.mockRejectedValue(new Error('internal service detail'));

    render(<App />);

    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      'Could not load your RepoGuard session. Check that the API is available and try again.',
    );
    expect(screen.queryByText('internal service detail')).toBeNull();
  });

  test('keeps the user signed in and shows a safe message when sign-out fails', async () => {
    globalThis.fetch
      .mockResolvedValueOnce(createSessionResponse())
      .mockResolvedValueOnce(createRepositoryResponse())
      .mockResolvedValueOnce({ ok: false, status: 500 });

    const user = userEvent.setup();
    render(<App />);

    const signOutButton = await screen.findByRole('button', { name: 'Sign out' });
    await user.click(signOutButton);

    expect(await screen.findByRole('alert')).toHaveProperty(
      'textContent',
      'Could not sign out. Please try again.',
    );
    expect(signOutButton.disabled).toBe(false);
  });
});
