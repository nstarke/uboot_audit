module.exports = function registerUploadRoute(app, deps) {
  const {
    dataDir,
    path,
    fsp,
    crypto,
    validUploadTypes,
    validContentTypes,
    normalizeContentType,
    sanitizeUploadPath,
    writeUploadFile,
    augmentJsonPayload,
    logPathForContentType,
    isValidMacAddress,
    verboseRequestLog,
    verboseResponseLog,
    getClientIp
  } = deps;

  function uploadDirectoryForType(baseDir, uploadType) {
    switch (uploadType) {
      case 'log':
      case 'logs':
        return path.join(baseDir, 'logs');
      case 'dmesg':
        return path.join(baseDir, 'dmesg');
      case 'file-list':
        return path.join(baseDir, 'file-list');
      case 'symlink-list':
        return path.join(baseDir, 'symlink-list');
      case 'orom':
        return path.join(baseDir, 'orom');
      case 'uboot-image':
        return path.join(baseDir, 'uboot', 'image');
      case 'uboot-environment':
        return path.join(baseDir, 'uboot', 'env');
      default:
        return path.join(baseDir, uploadType);
    }
  }

  function logFilePrefixForUploadType(targetDir, uploadType) {
    switch (uploadType) {
      case 'log':
      case 'logs':
        return path.join(targetDir, 'log');
      case 'dmesg':
        return path.join(targetDir, `dmesg.${new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z')}`);
      default:
        return path.join(targetDir, uploadType);
    }
  }

  async function writeSymlink(baseDir, relativePath, symlinkTarget) {
    const dest = path.resolve(baseDir, relativePath);
    if (!deps.isWithinRoot(dest, baseDir)) {
      throw new Error('invalid path');
    }
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    try {
      await fsp.unlink(dest);
    } catch (err) {
      if (err.code !== 'ENOENT') {
        throw err;
      }
    }
    await fsp.symlink(symlinkTarget, dest);
  }

  function sanitizeFileListPath(filePath) {
    if (!filePath || typeof filePath !== 'string') {
      return null;
    }

    const normalized = path.posix.normalize(filePath.replace(/\\/g, '/'));
    if (!normalized.startsWith('/')) {
      return null;
    }

    if (normalized === '/..' || normalized.startsWith('/../') || normalized.includes('/../')) {
      return null;
    }

    return normalized;
  }

  function fileListNameForPath(filePath) {
    if (filePath === '/') {
      return 'root-fs';
    }

    const stripped = filePath.replace(/^\/+/, '');
    return (stripped ? stripped.replace(/\//g, '-') : 'root');
  }

  app.post('/:mac/upload/:type', async (req, res) => {
    verboseRequestLog(req);
    const macAddress = String(req.params.mac || '').toLowerCase();
    const uploadType = req.params.type;
    const contentTypeHeader = req.get('Content-Type') || '';
    const normalizedContentType = normalizeContentType(contentTypeHeader);
    const payload = Buffer.isBuffer(req.body) ? req.body : Buffer.from([]);
    const timestamp = new Date().toISOString();
    const srcIp = getClientIp(req);
    const macDataDir = path.join(dataDir, macAddress);
    const requestedFilePath = sanitizeUploadPath(req.query.filePath);
    const symlink = req.query.symlink;
    const symlinkPath = req.query.symlinkPath;
    const wantsSymlink = symlink === 'true';

    if (!isValidMacAddress(macAddress)) {
      const body = 'invalid mac address\n';
      res.status(400).type('text').send(body);
      verboseResponseLog(req, 400, Buffer.byteLength(body));
      return;
    }

    if (uploadType !== 'file' && (symlink !== undefined || symlinkPath !== undefined)) {
      const body = 'symlink arguments only allowed for /upload/file\n';
      res.status(400).type('text').send(body);
      verboseResponseLog(req, 400, Buffer.byteLength(body));
      return;
    }

    if (symlink !== undefined && symlink !== 'true' && symlink !== 'false') {
      const body = 'invalid symlink value\n';
      res.status(400).type('text').send(body);
      verboseResponseLog(req, 400, Buffer.byteLength(body));
      return;
    }

    if (wantsSymlink && (!requestedFilePath || typeof symlinkPath !== 'string' || !symlinkPath.length)) {
      const body = 'symlink uploads require filePath and symlinkPath\n';
      res.status(400).type('text').send(body);
      verboseResponseLog(req, 400, Buffer.byteLength(body));
      return;
    }

    if (!wantsSymlink && symlinkPath !== undefined) {
      const body = 'symlinkPath requires symlink=true\n';
      res.status(400).type('text').send(body);
      verboseResponseLog(req, 400, Buffer.byteLength(body));
      return;
    }

    if (!validUploadTypes.has(uploadType)) {
      const body = 'invalid upload type\n';
      res.status(404).type('text').send(body);
      verboseResponseLog(req, 404, Buffer.byteLength(body));
      return;
    }

    if (!Object.prototype.hasOwnProperty.call(validContentTypes, normalizedContentType)) {
      const allowed = Object.keys(validContentTypes).sort().join(', ');
      const body = `unsupported content type; expected one of: ${allowed}\n`;
      res.status(415).type('text').send(body);
      verboseResponseLog(req, 415, Buffer.byteLength(body));
      return;
    }

    let payloadToLog = payload;
    let shouldTryJson = normalizedContentType.includes('json');

    if (!shouldTryJson) {
      try {
        payload.toString('utf8');
        shouldTryJson = true;
      } catch {
        shouldTryJson = false;
      }
    }

    if (shouldTryJson) {
      try {
        payloadToLog = augmentJsonPayload(payload, timestamp, srcIp);
      } catch {
        payloadToLog = payload;
      }
    }

    if (uploadType === 'file' && wantsSymlink) {
      try {
        await writeSymlink(path.join(macDataDir, 'fs'), requestedFilePath, symlinkPath);
      } catch {
        const body = 'invalid symlink upload\n';
        res.status(400).type('text').send(body);
        verboseResponseLog(req, 400, Buffer.byteLength(body));
        return;
      }
    } else if (uploadType === 'file' && requestedFilePath) {
      try {
        await writeUploadFile(path.join(macDataDir, 'fs'), requestedFilePath, payload);
      } catch {
        const body = 'invalid filePath\n';
        res.status(400).type('text').send(body);
        verboseResponseLog(req, 400, Buffer.byteLength(body));
        return;
      }
    } else {
      const targetDir = uploadDirectoryForType(macDataDir, uploadType);
      await fsp.mkdir(targetDir, { recursive: true });

      if (uploadType === 'file-list' || uploadType === 'symlink-list') {
        const requestedListPath = sanitizeFileListPath(req.query.filePath);
        if (!requestedListPath) {
          const body = `${uploadType} uploads require absolute filePath\n`;
          res.status(400).type('text').send(body);
          verboseResponseLog(req, 400, Buffer.byteLength(body));
          return;
        }

        const targetListPath = path.join(targetDir, fileListNameForPath(requestedListPath));
        await fsp.writeFile(
          targetListPath,
          payloadToLog[payloadToLog.length - 1] === 0x0a ? payloadToLog : Buffer.concat([payloadToLog, Buffer.from('\n')])
        );
      } else if (normalizedContentType === 'application/octet-stream') {
        const tsSafe = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z').replace(/:/g, '');
        const unique = crypto.randomUUID().replace(/-/g, '').slice(0, 8);
        const safeIp = srcIp.replace(/:/g, '_');
        const extension = uploadType === 'file' ? '.bin' : '.bin';
        const binaryPath = path.join(targetDir, `upload_${tsSafe}_${safeIp}_${unique}${extension}`);
        await fsp.writeFile(binaryPath, payload);
      } else {
        const targetLogPath = logPathForContentType(logFilePrefixForUploadType(targetDir, uploadType), contentTypeHeader);
        await fsp.mkdir(path.dirname(targetLogPath), { recursive: true });
        await fsp.appendFile(
          targetLogPath,
          payloadToLog[payloadToLog.length - 1] === 0x0a ? payloadToLog : Buffer.concat([payloadToLog, Buffer.from('\n')])
        );
      }
    }

    res.type('text').send('ok\n');
    verboseResponseLog(req, 200, 3);
  });
};