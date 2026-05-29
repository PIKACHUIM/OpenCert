// OpenCert Manager - Electron 主进程
// 功能：
//   1. 加载前端页面（连接本地 client-card 后端）
//   2. 关闭窗口时最小化到系统托盘
//   3. 托盘图标右键菜单（显示/退出）

const { app, BrowserWindow, Tray, Menu, nativeImage } = require('electron');
const path = require('path');

// 防止垃圾回收
let mainWindow = null;
let tray = null;

// 配置
const CONFIG = {
  // 前端页面地址（client-card 后端自带前端静态文件）
  frontendURL: 'http://127.0.0.1:1026',
  // 窗口尺寸
  width: 1280,
  height: 800,
  minWidth: 900,
  minHeight: 600,
};

function createWindow() {
  mainWindow = new BrowserWindow({
    width: CONFIG.width,
    height: CONFIG.height,
    minWidth: CONFIG.minWidth,
    minHeight: CONFIG.minHeight,
    title: 'OpenCert Manager',
    icon: getIconPath(),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    // 无边框可选（取消注释启用自定义标题栏）
    // frame: false,
    // titleBarStyle: 'hidden',
    show: false, // 先隐藏，加载完再显示避免白屏
  });

  // 加载前端页面
  mainWindow.loadURL(CONFIG.frontendURL).catch(() => {
    // 如果后端未启动，显示等待页面
    mainWindow.loadFile(path.join(__dirname, 'waiting.html'));
    // 每 2 秒重试
    const retryInterval = setInterval(() => {
      mainWindow.loadURL(CONFIG.frontendURL).then(() => {
        clearInterval(retryInterval);
      }).catch(() => { /* 继续重试 */ });
    }, 2000);
  });

  // 页面加载完成后显示窗口
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // 关闭窗口 → 最小化到托盘（而非退出）
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      // Windows 下显示气泡提示（仅首次）
      if (tray && !app._trayNotified) {
        tray.displayBalloon({
          title: 'OpenCert Manager',
          content: '程序已最小化到系统托盘，双击图标可重新打开。',
          iconType: 'info',
        });
        app._trayNotified = true;
      }
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createTray() {
  const icon = nativeImage.createFromPath(getIconPath());
  tray = new Tray(icon.resize({ width: 16, height: 16 }));

  const contextMenu = Menu.buildFromTemplate([
    {
      label: '显示主窗口',
      click: () => {
        if (mainWindow) {
          mainWindow.show();
          mainWindow.focus();
        }
      },
    },
    { type: 'separator' },
    {
      label: '退出',
      click: () => {
        app.isQuitting = true;
        app.quit();
      },
    },
  ]);

  tray.setToolTip('OpenCert Manager');
  tray.setContextMenu(contextMenu);

  // 双击托盘图标 → 显示窗口
  tray.on('double-click', () => {
    if (mainWindow) {
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

function getIconPath() {
  const iconName = process.platform === 'win32' ? 'icon.ico'
    : process.platform === 'darwin' ? 'icon.icns'
    : 'icon.png';
  const iconPath = path.join(__dirname, 'assets', iconName);
  // 如果图标文件不存在，返回空路径（Electron 会用默认图标）
  try {
    require('fs').accessSync(iconPath);
    return iconPath;
  } catch {
    return path.join(__dirname, 'assets', 'icon.png');
  }
}

// ---- 应用生命周期 ----

app.whenReady().then(() => {
  createTray();
  createWindow();

  app.on('activate', () => {
    // macOS: 点击 dock 图标时重新创建窗口
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    } else if (mainWindow) {
      mainWindow.show();
    }
  });
});

// 所有窗口关闭时不退出（托盘模式）
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    // Windows/Linux: 不退出，保持托盘
    // 如果需要退出，用户通过托盘菜单的"退出"
  }
});

// 应用退出前清理
app.on('before-quit', () => {
  app.isQuitting = true;
});
