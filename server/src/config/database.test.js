import { describe, expect, it } from '@jest/globals';
import { connectToDatabase } from './database.js';

describe('connectToDatabase configuration validation', () => {
  it('requires a non-empty MongoDB URI', async () => {
    await expect(connectToDatabase('')).rejects.toThrow(
      'MONGODB_URI is required to connect to the database.',
    );
    await expect(connectToDatabase('   ')).rejects.toThrow(
      'MONGODB_URI is required to connect to the database.',
    );
  });

  it.each([
    ['not-a-uri', 'MONGODB_URI must be a valid MongoDB connection URI.'],
    [
      'https://database.example',
      'MONGODB_URI must use mongodb:// or mongodb+srv://.',
    ],
  ])('rejects invalid URI %s before connecting', async (uri, message) => {
    await expect(connectToDatabase(uri)).rejects.toThrow(message);
  });
});
