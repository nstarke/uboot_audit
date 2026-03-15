// SPDX-License-Identifier: GPL-3.0-or-later - Copyright (c) 2026 Nicholas Starke
'use strict';

const fs = require('fs');
const crypto = require('crypto');

let validKeys = [];
let authRequired = false;

/* -------------------------------------------------------------------------
 * Initialisation
 * ---------------------------------------------------------------------- */

/**
 * Load bearer tokens from a key file and configure enforcement.
 *
 * @param {string}  [keyFile='ela.key']
 * @param {boolean} [enforced=false]  Pass true when --validate-key is set.
 *   - enforced=false: auth is not required regardless of key file contents.
 *   - enforced=true:  auth is required; returns false (caller should exit)
 *                     if no valid keys are found in the key file.
 * @returns {boolean} true on success, false when enforced but no keys found.
 */
function init(keyFile, enforced) {
  keyFile = keyFile || 'ela.key';
  enforced = Boolean(enforced);

  try {
    const content = fs.readFileSync(keyFile, 'utf8');
    validKeys = content
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
  } catch (_) {
    validKeys = [];
  }

  if (enforced && validKeys.length === 0) {
    authRequired = false;
    return false; /* caller must warn and exit */
  }

  authRequired = enforced;
  return true;
}

/* -------------------------------------------------------------------------
 * Constant-time comparison
 * ---------------------------------------------------------------------- */

/**
 * Constant-time comparison of two strings.
 * Pads both to the same length before comparing so the result does not
 * leak the length of either value through timing.
 */
function constantTimeEqual(a, b) {
  const maxLen = Math.max(a.length, b.length, 1);
  const aBuf = Buffer.alloc(maxLen, 0);
  const bBuf = Buffer.alloc(maxLen, 0);
  Buffer.from(a, 'utf8').copy(aBuf, 0, 0, Math.min(a.length, maxLen));
  Buffer.from(b, 'utf8').copy(bBuf, 0, 0, Math.min(b.length, maxLen));
  return crypto.timingSafeEqual(aBuf, bBuf);
}

/* -------------------------------------------------------------------------
 * Token validation
 * ---------------------------------------------------------------------- */

/**
 * Check an Authorization header value against all loaded tokens.
 * Always iterates every token (no short-circuit) to avoid timing oracles.
 * Returns true if auth is not required or the token matches any loaded key.
 *
 * @param {string|undefined} authHeader  Value of the Authorization header.
 * @returns {boolean}
 */
function checkBearer(authHeader) {
  if (!authRequired) return true;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;

  const token = authHeader.slice(7);
  let ok = false;
  for (const key of validKeys) {
    if (constantTimeEqual(token, key)) ok = true; /* no break — constant time */
  }
  return ok;
}

/* -------------------------------------------------------------------------
 * Express middleware
 * ---------------------------------------------------------------------- */

/**
 * Express middleware that rejects requests without a valid bearer token
 * with HTTP 401.  Passes through when auth is not required.
 */
function middleware(req, res, next) {
  if (checkBearer(req.headers['authorization'])) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

module.exports = { init, checkBearer, middleware };
