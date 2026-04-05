#!/bin/sh

# 生成运行时配置
echo "生成运行时配置..."

# 确保静态文件目录存在
CONFIG_DIR=/usr/share/nginx/html
CONFIG_FILE=${CONFIG_DIR}/config.js

# 检查目录存在
if [ ! -d "$CONFIG_DIR" ]; then
  echo "错误: 静态文件目录不存在: $CONFIG_DIR"
  exit 1
fi

# 生成配置文件
cat > ${CONFIG_FILE} << EOF
// 运行时配置 - 由Docker容器启动脚本生成
window.appConfig = {
  backendUrl: '${BACKEND_URL:-http://localhost:8787}'
};
EOF

# 验证文件生成
if [ -f "$CONFIG_FILE" ]; then
  echo "配置文件已成功生成: $CONFIG_FILE"
  echo "配置已更新: BACKEND_URL=${BACKEND_URL:-http://localhost:8787}"
  echo "配置文件内容:"
  cat ${CONFIG_FILE}
else
  echo "错误: 配置文件未成功生成: $CONFIG_FILE"
fi

# 查看静态目录中的文件列表，帮助调试
echo "静态目录文件列表:"
ls -la ${CONFIG_DIR}

# 启动nginx
echo "启动Nginx..."
exec nginx -g 'daemon off;' 