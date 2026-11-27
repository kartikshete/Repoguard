import mongoose from 'mongoose';

const MAX_FINDINGS_PER_SCAN = 1000;
const repositoryFullNamePattern =
  /^[A-Za-z0-9][A-Za-z0-9_.-]{0,38}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
const commitShaPattern = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i;

function isSafeRepositoryPath(value) {
  if (value === null) {
    return true;
  }

  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 1024 ||
    value.startsWith('/') ||
    value.includes('\\')
  ) {
    return false;
  }

  return value
    .split('/')
    .every((segment) => segment !== '' && segment !== '.' && segment !== '..');
}

function isSafeHttpsUrl(value) {
  if (value === null) {
    return true;
  }

  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' && !url.username && !url.password && !url.port
    );
  } catch {
    return false;
  }
}

function isSafeLineNumber(value) {
  return value === null || (Number.isSafeInteger(value) && value >= 1);
}

export const scanFindingSchema = new mongoose.Schema(
  {
    tool: {
      type: String,
      required: true,
      enum: ['semgrep', 'eslint', 'npm-audit', 'gemini'],
    },
    ruleId: {
      type: String,
      trim: true,
      maxlength: 200,
      default: null,
    },
    severity: {
      type: String,
      required: true,
      enum: ['critical', 'high', 'medium', 'low', 'info'],
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200,
    },
    message: {
      type: String,
      required: true,
      trim: true,
      maxlength: 5000,
    },
    filePath: {
      type: String,
      default: null,
      maxlength: 1024,
      validate: {
        validator: isSafeRepositoryPath,
        message: 'Finding file paths must be safe relative paths.',
      },
    },
    startLine: {
      type: Number,
      default: null,
      min: 1,
      validate: {
        validator: isSafeLineNumber,
        message: 'Finding line numbers must be positive integers.',
      },
    },
    endLine: {
      type: Number,
      default: null,
      min: 1,
      validate: {
        validator: isSafeLineNumber,
        message: 'Finding line numbers must be positive integers.',
      },
    },
    referenceUrl: {
      type: String,
      default: null,
      maxlength: 2048,
      validate: {
        validator: isSafeHttpsUrl,
        message: 'Finding reference URLs must use HTTPS.',
      },
    },
  },
  { _id: false, strict: 'throw' },
);

export const scanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      immutable: true,
    },
    githubRepositoryId: {
      type: Number,
      required: true,
      immutable: true,
      min: 1,
      validate: {
        validator: Number.isSafeInteger,
        message: 'GitHub repository IDs must be safe integers.',
      },
    },
    repositoryFullName: {
      type: String,
      required: true,
      immutable: true,
      trim: true,
      maxlength: 140,
      match: [
        repositoryFullNamePattern,
        'Repository names must use an owner/repository format.',
      ],
    },
    defaultBranch: {
      type: String,
      required: true,
      immutable: true,
      trim: true,
      maxlength: 255,
    },
    commitSha: {
      type: String,
      required: true,
      immutable: true,
      trim: true,
      lowercase: true,
      match: [commitShaPattern, 'Commit SHA has an invalid format.'],
    },
    status: {
      type: String,
      required: true,
      enum: ['queued', 'running', 'completed', 'failed'],
      default: 'queued',
    },
    findings: {
      type: [scanFindingSchema],
      default: [],
      validate: {
        validator: (findings) => findings.length <= MAX_FINDINGS_PER_SCAN,
        message: `A scan cannot store more than ${MAX_FINDINGS_PER_SCAN} findings.`,
      },
    },
    completedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    versionKey: false,
    strict: 'throw',
  },
);

scanSchema.index({ userId: 1, createdAt: -1 });
scanSchema.index({ status: 1, createdAt: 1 });

const Scan = mongoose.models.Scan ?? mongoose.model('Scan', scanSchema);

export default Scan;
