import mongoose from 'mongoose';

let connectionAttempt;

function validateMongoUri(uri) {
  let protocol;

  try {
    protocol = new URL(uri).protocol;
  } catch {
    throw new Error('MONGODB_URI must be a valid MongoDB connection URI.');
  }

  if (protocol !== 'mongodb:' && protocol !== 'mongodb+srv:') {
    throw new Error('MONGODB_URI must use mongodb:// or mongodb+srv://.');
  }
}

export async function connectToDatabase(uri = process.env.MONGODB_URI) {
  if (typeof uri !== 'string' || uri.trim() === '') {
    throw new Error('MONGODB_URI is required to connect to the database.');
  }

  const normalizedUri = uri.trim();
  validateMongoUri(normalizedUri);

  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (!connectionAttempt) {
    connectionAttempt = mongoose
      .connect(normalizedUri, {
        autoIndex: process.env.NODE_ENV !== 'production',
        serverSelectionTimeoutMS: 10_000,
      })
      .then(() => mongoose.connection)
      .catch((error) => {
        connectionAttempt = undefined;
        throw new Error('MongoDB connection failed.', { cause: error });
      });
  }

  return connectionAttempt;
}

export async function disconnectFromDatabase() {
  connectionAttempt = undefined;

  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
}
