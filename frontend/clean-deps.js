/**
 * 清理Vite依赖缓存的脚本
 * 当遇到依赖问题时运行: node clean-deps.js
 * npm run clean
 */

import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import { fileURLToPath } from "url";

// 获取当前文件的目录名
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 要清理的目录
const directoriesToClean = [path.join(__dirname, "node_modules", ".vite"), path.join(__dirname, "node_modules", ".cache")];

// 清理缓存目录
directoriesToClean.forEach((dir) => {
  if (fs.existsSync(dir)) {
    console.log(`正在清理: ${dir}`);
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      console.log(`✅ 清理完成: ${dir}`);
    } catch (err) {
      console.error(`❌ 清理失败: ${dir}`, err);
    }
  } else {
    console.log(`目录不存在，跳过: ${dir}`);
  }
});

// 清理package-lock.json
const packageLockPath = path.join(__dirname, "package-lock.json");
if (fs.existsSync(packageLockPath)) {
  console.log("正在清理: package-lock.json");
  try {
    fs.unlinkSync(packageLockPath);
    console.log("✅ 已删除 package-lock.json");
  } catch (err) {
    console.error("❌ 删除 package-lock.json 失败", err);
  }
}

// 重新安装依赖
console.log("正在重新安装依赖...");
try {
  execSync("npm install", { stdio: "inherit" });
  console.log("✅ 依赖安装完成");
} catch (err) {
  console.error("❌ 依赖安装失败", err);
}

console.log("清理完成! 现在运行 npm run dev 启动开发服务器");
