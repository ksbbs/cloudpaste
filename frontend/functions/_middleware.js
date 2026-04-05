/**
 * Cloudflare Pages中间件
 * 用于在运行时动态替换配置文件中的环境变量
 */
export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 只处理对config.js的请求
  if (url.pathname === "/config.js") {
    // 获取原始的配置文件
    const response = await next();
    const originalText = await response.text();

    // 替换占位符为实际的环境变量值
    // 如果环境变量不存在，则使用默认的开发环境URL
    const backendUrl = env.VITE_BACKEND_URL || "http://localhost:8787";
    const modifiedText = originalText.replace("__BACKEND_URL__", backendUrl);

    // 返回修改后的配置文件
    return new Response(modifiedText, {
      headers: {
        "Content-Type": "application/javascript",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    });
  }

  // 对于其他请求，正常处理
  return next();
}
