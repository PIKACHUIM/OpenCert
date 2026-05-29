# OpenCert Manager Desktop

基于 Electron 的桌面客户端，包装 OpenCert Manager 前端界面。

## 功能

- 加载本地 client-card 后端提供的 Web 前端
- 关闭窗口最小化到系统托盘（而非退出）
- 托盘图标右键菜单：显示主窗口 / 退出
- 双击托盘图标恢复窗口
- 后端未就绪时显示等待页面并自动重试

## 使用方式

### 开发运行

```bash
cd desktop
npm install
npm start
```

> 注意：需要先启动 client-card 后端（默认监听 127.0.0.1:9527）

### 打包发布

```bash
# Windows
npm run build:win

# macOS
npm run build:mac

# Linux
npm run build:linux
```

## 目录结构

```
desktop/
├── main.js          # Electron 主进程
├── preload.js       # 预加载脚本（安全暴露 API）
├── waiting.html     # 后端等待页面
├── package.json     # 项目配置 + electron-builder 打包配置
├── assets/          # 图标资源
│   ├── icon.ico     # Windows 图标
│   ├── icon.icns    # macOS 图标
│   └── icon.png     # Linux 图标 (256x256)
└── dist/            # 打包输出目录
```

## 配置

编辑 `main.js` 中的 `CONFIG` 对象：

```js
const CONFIG = {
  frontendURL: 'http://127.0.0.1:9527',  // 后端地址
  width: 1280,                             // 窗口宽度
  height: 800,                             // 窗口高度
};
```

## 图标

将应用图标放入 `assets/` 目录：
- `icon.ico` - Windows 图标（包含 16/32/48/64/128/256 尺寸）
- `icon.icns` - macOS 图标
- `icon.png` - Linux 图标（至少 256x256）

可使用在线工具从 PNG 转换：https://www.icoconverter.com/
