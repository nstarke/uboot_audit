module.exports = function registerUbootEnvRoute(app, deps) {
  const { envDir, fsp, isWithinRoot, verboseRequestLog, verboseResponseLog } = deps;

  app.get('/uboot-env/:env_filename', async (req, res) => {
    verboseRequestLog(req);
    const candidate = deps.path.resolve(envDir, req.params.env_filename);
    if (!isWithinRoot(candidate, envDir)) {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
      return;
    }
    try {
      const stat = await fsp.stat(candidate);
      if (!stat.isFile()) {
        throw new Error('not a file');
      }
      res.sendFile(candidate);
    } catch {
      res.status(404).type('text').send('not found\n');
      verboseResponseLog(req, 404, 10);
    }
  });
};