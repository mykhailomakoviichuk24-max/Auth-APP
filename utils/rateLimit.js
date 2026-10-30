// Простий лімітер за ключем (IP) у пам'яті — додатковий шар до блокування акаунтів.
function rateLimit({ windowMs, max, message }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
  }, windowMs).unref();

  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    let h = hits.get(key);
    if (!h || h.reset < now) h = { count: 0, reset: now + windowMs };
    h.count++;
    hits.set(key, h);
    if (h.count > max) {
      res.status(429);
      return res.render('error', { title: 'Забагато запитів', message: message || 'Забагато запитів. Спробуйте пізніше.' });
    }
    next();
  };
}

module.exports = rateLimit;
