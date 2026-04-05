/**
 * Vercel专用构建脚本
 * 用于在构建时生成包含环境变量的配置文件
 */
const fs = require("fs");
const path = require("path");

// 获取环境变量，如果不存在则使用默认值
const backendUrl = process.env.VITE_BACKEND_URL || "http://localhost:8787";

console.log(`Vercel构建: 使用后端URL ${backendUrl}`);

// 配置内容
const configContent = `// 运行时配置 - 由Vercel构建脚本生成
window.appConfig = {
  backendUrl: '${backendUrl}'
};
`;

// 确保public目录存在
const publicDir = path.resolve(__dirname, "public");
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}

// 写入配置文件
fs.writeFileSync(path.resolve(publicDir, "config.js"), configContent, "utf8");

console.log("✅ 配置文件已生成");
