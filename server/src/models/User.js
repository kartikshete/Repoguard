import mongoose from 'mongoose';

const githubUsernamePattern = /^[A-Za-z0-9](?:-?[A-Za-z0-9])*$/;

function isHttpsUrl(value) {
  if (!value) {
    return true;
  }

  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

export const userSchema = new mongoose.Schema(
  {
    githubId: {
      type: String,
      required: true,
      unique: true,
      immutable: true,
      trim: true,
      maxlength: 32,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
      maxlength: 39,
      match: [githubUsernamePattern, 'GitHub username has an invalid format.'],
    },
    displayName: {
      type: String,
      trim: true,
      maxlength: 100,
      default: '',
    },
    avatarUrl: {
      type: String,
      trim: true,
      maxlength: 2048,
      default: '',
      validate: {
        validator: isHttpsUrl,
        message: 'Avatar URL must use HTTPS.',
      },
    },
  },
  {
    timestamps: true,
    versionKey: false,
    strict: 'throw',
  },
);

const User = mongoose.models.User ?? mongoose.model('User', userSchema);

export default User;
