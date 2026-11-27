import { rateLimit } from 'express-rate-limit';
import { Router } from 'express';
import { requireAuth } from '../auth/requireAuth.js';
import Scan from '../models/Scan.js';

const router = Router();
const SCAN_ID_PATTERN = /^[a-f0-9]{24}$/i;
const DEFAULT_PAGE_SIZE = 20;
const MAX_PAGE_SIZE = 50;

const scanReadRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Scan read rate limit exceeded.' },
});

router.use(requireAuth, scanReadRateLimit);

function toScanSummary(scan) {
  return {
    id: scan._id.toString(),
    repositoryFullName: scan.repositoryFullName,
    defaultBranch: scan.defaultBranch,
    commitSha: scan.commitSha,
    status: scan.status,
    createdAt: scan.createdAt,
    completedAt: scan.completedAt,
  };
}

function toScanDetails(scan) {
  return {
    ...toScanSummary(scan),
    findings: scan.findings.map((finding) => ({
      tool: finding.tool,
      ruleId: finding.ruleId,
      severity: finding.severity,
      title: finding.title,
      message: finding.message,
      filePath: finding.filePath,
      startLine: finding.startLine,
      endLine: finding.endLine,
      referenceUrl: finding.referenceUrl,
    })),
  };
}

function parsePageSize(value) {
  if (value === undefined) {
    return DEFAULT_PAGE_SIZE;
  }

  if (
    typeof value !== 'string' ||
    !/^(?:[1-9]|[1-4][0-9]|50)$/.test(value)
  ) {
    return null;
  }

  return Number(value);
}

router.get('/', async (request, response, next) => {
  response.set('Cache-Control', 'private, no-store');
  const pageSize = parsePageSize(request.query.limit);
  const cursor = request.query.cursor;

  if (
    pageSize === null ||
    (cursor !== undefined &&
      (typeof cursor !== 'string' || !SCAN_ID_PATTERN.test(cursor)))
  ) {
    return response.status(400).json({ error: 'Scan history query is invalid.' });
  }

  try {
    const filter = { userId: request.auth.userId };

    if (cursor) {
      const cursorScan = await Scan.findOne({
        _id: cursor,
        userId: request.auth.userId,
      })
        .select('_id createdAt')
        .lean();

      if (!cursorScan) {
        return response.status(400).json({ error: 'Scan history cursor is invalid.' });
      }

      filter.$or = [
        { createdAt: { $lt: cursorScan.createdAt } },
        { createdAt: cursorScan.createdAt, _id: { $lt: cursorScan._id } },
      ];
    }

    const results = await Scan.find(filter)
      .select(
        '_id repositoryFullName defaultBranch commitSha status createdAt completedAt',
      )
      .sort({ createdAt: -1, _id: -1 })
      .limit(pageSize + 1)
      .lean();
    const hasMore = results.length > pageSize;
    const scans = results.slice(0, pageSize);

    return response.status(200).json({
      scans: scans.map(toScanSummary),
      nextCursor: hasMore ? scans.at(-1)._id.toString() : null,
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/:scanId', async (request, response, next) => {
  response.set('Cache-Control', 'private, no-store');

  if (!SCAN_ID_PATTERN.test(request.params.scanId)) {
    return response.status(400).json({ error: 'Scan ID is invalid.' });
  }

  try {
    const scan = await Scan.findOne({
      _id: request.params.scanId,
      userId: request.auth.userId,
    })
      .select(
        '_id repositoryFullName defaultBranch commitSha status findings createdAt completedAt',
      )
      .lean();

    if (!scan) {
      return response.status(404).json({ error: 'Scan was not found.' });
    }

    return response.status(200).json({ scan: toScanDetails(scan) });
  } catch (error) {
    return next(error);
  }
});

export default router;
