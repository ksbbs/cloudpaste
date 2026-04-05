/**
 * Rate Limiting 中间件
 * 基于内存的请求频率限制，适用于 Cloudflare Workers 免费计划
 *
 * 注意：内存存储在 Worker 实例间不共享，适合单实例场景
 * 如需更严格的限制，可升级 Cloudflare 付费计划使用 [[ratelimits]]
 */

// 内存存储
const rateLimitStore = new Map();

/**
 * 清理过期记录（定期执行）
 */
const cleanupInterval = 60 * 1000; // 每分钟清理一次
let lastCleanup = Date.now();

const cleanupStore = () => {
  const now = Date.now();
  if (now - lastCleanup < cleanupInterval) return;

  lastCleanup = now;
  const maxAge = 10 * 60 * 1000; // 清理 10 分钟前的记录

  for (const [key, record] of rateLimitStore.entries()) {
    const validTimestamps = record.timestamps.filter(ts => now - ts < maxAge);
    if (validTimestamps.length === 0) {
      rateLimitStore.delete(key);
    } else {
      record.timestamps = validTimestamps;
    }
  }
};

/**
 * 创建 Rate Limiting 中间件
 * @param {Object} options
 * @param {number} options.windowMs - 时间窗口（毫秒）
 * @param {number} options.maxRequests - 时间窗口内最大请求数
 * @param {Function} options.keyGenerator - 生成限流 key 的函数
 * @param {string} options.message - 超限时的错误消息
 */
export const createRateLimit = (options = {}) => {
  const {
    windowMs = 60 * 1000,      // 默认 1 分钟
    maxRequests = 60,          // 默认 60 次
    keyGenerator = (c) =>
      c.req.header("cf-connecting-ip") ||
      c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ||
      "unknown",
    message = "请求过于频繁，请稍后再试",
    skipCondition = null,      // 可选：跳过限流的条件函数
  } = options;

  return async (c, next) => {
    // 定期清理过期记录
    cleanupStore();

    // 可选：跳过某些请求
    if (skipCondition && await skipCondition(c)) {
      return next();
    }

    const key = keyGenerator(c);
    const now = Date.now();
    const windowStart = now - windowMs;

    // 获取或初始化记录
    let record = rateLimitStore.get(key);
    if (!record) {
      record = { timestamps: [] };
      rateLimitStore.set(key, record);
    }

    // 清理过期时间戳
    record.timestamps = record.timestamps.filter(ts => ts > windowStart);

    // 检查是否超限
    if (record.timestamps.length >= maxRequests) {
      const oldestTimestamp = record.timestamps[0];
      const retryAfter = Math.ceil((oldestTimestamp + windowMs - now) / 1000);

      c.header("Retry-After", String(retryAfter));
      c.header("X-RateLimit-Limit", String(maxRequests));
      c.header("X-RateLimit-Remaining", "0");
      c.header("X-RateLimit-Reset", String(Math.ceil((oldestTimestamp + windowMs) / 1000)));

      console.log(JSON.stringify({
        type: "rate_limit",
        key,
        path: c.req.path,
        method: c.req.method,
        retryAfter,
      }));

      return c.json({
        success: false,
        code: "RATE_LIMIT_EXCEEDED",
        message,
        data: { retryAfter },
      }, 429);
    }

    // 记录本次请求
    record.timestamps.push(now);

    // 设置响应头
    c.header("X-RateLimit-Limit", String(maxRequests));
    c.header("X-RateLimit-Remaining", String(Math.max(0, maxRequests - record.timestamps.length)));

    await next();
  };
};

/**
 * 预定义的限流策略
 */
export const rateLimits = {
  // 严格限制 - 登录等敏感操作：5 分钟内最多 10 次
  strict: createRateLimit({
    windowMs: 5 * 60 * 1000,
    maxRequests: 10,
    message: "登录尝试过多，请 5 分钟后再试"
  }),

  // 中等限制 - 普通 API 操作：1 分钟内最多 30 次
  moderate: createRateLimit({
    windowMs: 60 * 1000,
    maxRequests: 30,
    message: "操作过于频繁，请稍后再试",
  }),

  // 宽松限制 - 上传等重操作：1 分钟内最多 60 次
  relaxed: createRateLimit({
    windowMs: 60 * 1000,
    maxRequests: 60,
    message: "请求过于频繁，请稍后再试",
  }),

  // 全局限制 - 所有请求：1 分钟内最多 120 次
  global: createRateLimit({
    windowMs: 60 * 1000,
    maxRequests: 120,
    message: "请求过于频繁，请稍后再试",
  }),
};

/**
 * 基于用户 ID 的限流 Key 生成器
 * 用于需要按用户而非 IP 限流的场景
 */
export const userKeyGenerator = (c) => {
  const authResult = c.get("authResult");
  const userId = authResult?.getUserId?.();
  const ip = c.req.header("cf-connecting-ip") || "unknown";
  return userId ? `user:${userId}` : `ip:${ip}`;
};

/**
 * 组合 Key 生成器（IP + 路径）
 * 用于按路径分别限流的场景
 */
export const pathKeyGenerator = (c) => {
  const ip = c.req.header("cf-connecting-ip") ||
             c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ||
             "unknown";
  const path = c.req.path;
  return `${ip}:${path}`;
};
