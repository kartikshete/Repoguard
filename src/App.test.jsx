import { afterEach, beforeEach, describe, expect, jest, test } from '@jest/globals';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App.jsx';

beforeEach(() => {
  globalThis.fetch = jest.fn();
});

afterEach(() => {
  cleanup();
});

describe('App authentication flow', () => {
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
      await screen.findByRole('heading', { name: 'Connect your GitHub account' }),
    ).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Continue with GitHub' }).getAttribute('href')).toBe(
      '/api/auth/github',
    );
  });

  test('shows the authenticated profile and signs out successfully', async () => {
    globalThis.fetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          user: { username: 'kartik', displayName: 'Kartik Shete' },
        }),
      })
      .mockResolvedValueOnce({ ok: true, status: 204 });

    const user = userEvent.setup();
    render(<App />);

    expect(
      await screen.findByRole('heading', { name: 'Welcome, Kartik Shete' }),
    ).toBeTruthy();
    expect(screen.getByText('@kartik')).toBeTruthy();

    await user.click(await screen.findByRole('button', { name: 'Sign out' }));

    expect(
      await screen.findByRole('link', { name: 'Continue with GitHub' }),
    ).toBeTruthy();
    expect(globalThis.fetch).toHaveBeenNthCalledWith(2, '/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
    });
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
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ user: { username: 'kartik' } }),
      })
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
