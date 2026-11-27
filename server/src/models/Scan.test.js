import { describe, expect, it } from '@jest/globals';
import mongoose from 'mongoose';
import Scan from './Scan.js';

function createValidScan(overrides = {}) {
  return new Scan({
    userId: new mongoose.Types.ObjectId(),
    githubRepositoryId: 42,
    repositoryFullName: 'kartik/repoguard',
    defaultBranch: 'main',
    commitSha: 'a'.repeat(40),
    ...overrides,
  });
}

function createValidFinding(overrides = {}) {
  return {
    tool: 'semgrep',
    ruleId: 'javascript.lang.security.audit.xss',
    severity: 'high',
    title: 'Potential cross-site scripting',
    message: 'Review the untrusted value before rendering it.',
    filePath: 'src/components/Example.jsx',
    startLine: 12,
    endLine: 14,
    referenceUrl: 'https://semgrep.dev/rules/example',
    ...overrides,
  };
}

describe('Scan model', () => {
  it('defaults a valid scan to queued with no findings', async () => {
    const scan = createValidScan();

    await expect(scan.validate()).resolves.toBeUndefined();
    expect(scan.status).toBe('queued');
    expect(scan.findings).toHaveLength(0);
    expect(scan.completedAt).toBeNull();
  });

  it('accepts a valid finding without storing a source snippet', async () => {
    const scan = createValidScan({ findings: [createValidFinding()] });

    await expect(scan.validate()).resolves.toBeUndefined();
    expect(scan.findings[0].filePath).toBe('src/components/Example.jsx');
    expect(scan.findings[0].toObject()).not.toHaveProperty('_id');
  });

  it('normalizes a 64-character commit SHA', async () => {
    const scan = createValidScan({ commitSha: 'A'.repeat(64) });

    await expect(scan.validate()).resolves.toBeUndefined();
    expect(scan.commitSha).toBe('a'.repeat(64));
  });

  it.each(['owner', '../private/repo', 'owner/has spaces'])(
    'rejects invalid repository identifiers: %s',
    async (repositoryFullName) => {
      const scan = createValidScan({ repositoryFullName });

      await expect(scan.validate()).rejects.toThrow();
    },
  );

  it('rejects a malformed commit SHA', async () => {
    const scan = createValidScan({ commitSha: 'not-a-commit' });

    await expect(scan.validate()).rejects.toThrow();
  });

  it.each(['../secrets.env', '/etc/passwd', 'src\\secret.js'])(
    'rejects an unsafe finding path: %s',
    async (filePath) => {
      const scan = createValidScan({
        findings: [createValidFinding({ filePath })],
      });

      await expect(scan.validate()).rejects.toThrow(
        'Finding file paths must be safe relative paths.',
      );
    },
  );

  it('rejects non-integer finding line numbers', async () => {
    const scan = createValidScan({
      findings: [createValidFinding({ startLine: 12.5 })],
    });

    await expect(scan.validate()).rejects.toThrow(
      'Finding line numbers must be positive integers.',
    );
  });

  it('rejects non-HTTPS finding references', async () => {
    const scan = createValidScan({
      findings: [createValidFinding({ referenceUrl: 'http://example.com/rule' })],
    });

    await expect(scan.validate()).rejects.toThrow(
      'Finding reference URLs must use HTTPS.',
    );
  });

  it('caps the number of findings stored in one scan', async () => {
    const findings = Array.from({ length: 1001 }, (_, index) =>
      createValidFinding({ title: `Finding ${index}` }),
    );
    const scan = createValidScan({ findings });

    await expect(scan.validate()).rejects.toThrow(
      'A scan cannot store more than 1000 findings.',
    );
  });

  it('rejects undeclared source-code fields', () => {
    expect(() => createValidScan({ sourceCode: 'sensitive source' })).toThrow();
    expect(() =>
      createValidScan({
        findings: [createValidFinding({ codeSnippet: 'secret' })],
      }),
    ).toThrow();
  });
});
