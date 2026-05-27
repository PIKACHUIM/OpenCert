// OpenCert Manager — Electron 主进程
// 功能：
//   1. 自动拉起同目录下的 client-card(.exe) 后端进程
//   2. 轮询 /api/health 等待后端就绪后再加载前端
//   3. 后端异常退出时托盘变红 + UI 通知 + 支持重启
//   4. 退出时优雅关闭后端（SIGTERM → 5s 超时 → SIGKILL）
//   5. IPC 通道 register-pkcs11-mock：根据 OS 注册 pkcs11-mock 到系统
const { app, BrowserWindow, Tray, Menu, nativeImage, ipcMain, dialog } = require('electron');
const { spawn, execSync } = require('child_process');
const path = require('path');
const http = require('http');
const fs = require('fs');

let mainWindow = null;
let tray = null;
let backendProcess = null;
let backendReady = false;
let isQuitting = false;

// ---- 后端可执行文件路径 ----
function getBackendPath() {
  const ext = process.platform === 'win32' ? '.exe' : '';
  // 开发模式：同级目录；打包模式：extraResources
  const candidates = [
    path.join(__dirname, `../client-card${ext}`),
    path.join(__dirname, `../../client-card${ext}`),
    path.join(process.resourcesPath || '', `client-card${ext}`),
    path.join(app.getAppPath(), `../client-card${ext}`),
  ];
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return p; } catch { /* ignore */ }
  }
  return null;
}

// ---- 健康检查 ----
function checkHealth(port = 1026, timeout = 2000) {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:${port}/api/health`, { timeout }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => resolve(res.statusCode === 200));
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

// ---- 等待后端就绪（最长 10 秒）----
async function waitForBackend(port = 1026, maxWaitMs = 10000) {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    if (await checkHealth(port)) return true;
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

// ---- 启动后端进程 ----
function spawnBackend() {
  const binPath = getBackendPath();
  if (!binPath) return null;

  const configPath = path.join(app.getPath('userData'), 'config.yaml');
  const args = [];
  if (fs.existsSync(configPath)) {
    args.push(`--config=${configPath}`);
  }

  console.log(`[Electron] 启动后端: ${binPath} ${args.join(' ')}`);
  const child = spawn(binPath, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
    windowsHide: true,
  });

  child.stdout?.on('data', (d) => console.log(`[backend] ${d.toString().trim()}`));
  child.stderr?.on('data', (d) => console.error(`[backend:err] ${d.toString().trim()}`));

  child.on('exit', (code, signal) => {
    console.log(`[Electron] 后端退出: code=${code} signal=${signal}`);
    backendProcess = null;
    backendReady = false;
    if (!isQuitting) {
      // 非正常退出：更新托盘 + 通知前端
      updateTrayStatus(false);
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('backend-down', { code, signal });
      }
    }
  });

  child.on('error', (err) => {
    console.error(`[Electron] 后端启动失败:`, err.message);
    backendProcess = null;
  });

  return child;
}

// ---- 停止后端进程 ----
function stopBackend() {
  if (!backendProcess) return Promise.resolve();
  return new Promise((resolve) => {
    const pid = backendProcess.pid;
    console.log(`[Electron] 停止后端 PID=${pid}`);

    // 先发 SIGTERM
    try {
      if (process.platform === 'win32') {
        // Windows 无 SIGTERM，用 taskkill
        execSync(`taskkill /PID ${pid} /T`, { stdio: 'ignore' });
      } else {
        backendProcess.kill('SIGTERM');
      }
    } catch { /* ignore */ }

    // 5 秒超时后强杀
    const timer = setTimeout(() => {
      try {
        if (process.platform === 'win32') {
          execSync(`taskkill /PID ${pid} /F /T`, { stdio: 'ignore' });
        } else {
          backendProcess?.kill('SIGKILL');
        }
      } catch { /* ignore */ }
      resolve();
    }, 5000);

    backendProcess.on('exit', () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

// ---- 托盘状态更新 ----
function updateTrayStatus(online) {
  if (!tray) return;
  const label = online ? 'OpenCert Manager — 运行中' : 'OpenCert Manager — 后端离线';
  tray.setToolTip(label);
  // 重建菜单以反映状态
  const contextMenu = Menu.buildFromTemplate([
    {
      label: '显示主窗口',
      click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus(); } },
    },
    { type: 'separator' },
    {
      label: online ? '✅ 后端运行中' : '❌ 后端离线',
      enabled: false,
    },
    {
      label: '重启后端',
      click: async () => {
        await stopBackend();
        backendProcess = spawnBackend();
        if (backendProcess) {
          const ok = await waitForBackend();
          backendReady = ok;
          updateTrayStatus(ok);
          if (ok && mainWindow && !mainWindow.isDestroyed()) {
            mainWindow.webContents.send('backend-up');
          }
        }
      },
    },
    { type: 'separator' },
    {
      label: '退出',
      click: () => {
        isQuitting = true;
        app.quit();
      },
    },
  ]);
  tray.setContextMenu(contextMenu);
}

// ---- 创建主窗口 ----
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 960,
    minHeight: 600,
    title: 'OpenCert Manager',
    icon: path.join(__dirname, '../public/icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.cjs'),
    },
  });

  // 加载构建后的前端页面
  const indexPath = path.join(__dirname, '../dist/index.html');
  mainWindow.loadFile(indexPath);

  // 关闭时最小化到托盘而非退出
  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ---- 创建托盘 ----
function createTray() {
  const iconPath = path.join(__dirname, '../public/icon.png');
  let trayIcon;
  try {
    trayIcon = nativeImage.createFromPath(iconPath);
    if (trayIcon.isEmpty()) trayIcon = nativeImage.createEmpty();
  } catch {
    trayIcon = nativeImage.createEmpty();
  }

  tray = new Tray(trayIcon);
  tray.on('double-click', () => {
    if (mainWindow) { mainWindow.show(); mainWindow.focus(); }
  });
  updateTrayStatus(false);
}

// ---- IPC：注册 pkcs11-mock 到系统 ----
ipcMain.handle('register-pkcs11-mock', async () => {
  try {
    const ext = process.platform === 'win32' ? '.dll' : '.so';
    const mockPath = [
      path.join(__dirname, `../pkcs11-mock${ext}`),
      path.join(process.resourcesPath || '', `pkcs11-mock${ext}`),
    ].find((p) => { try { return fs.existsSync(p); } catch { return false; } });

    if (!mockPath) {
      return { success: false, error: '未找到 pkcs11-mock 文件' };
    }

    if (process.platform === 'win32') {
      // Windows: regsvr32（需要管理员权限）
      execSync(`regsvr32 /s "${mockPath}"`, { stdio: 'ignore' });
    } else if (process.platform === 'darwin') {
      // macOS: 写入 ~/Library/Security/tokend
      const dest = path.join(app.getPath('home'), 'Library/Security');
      fs.mkdirSync(dest, { recursive: true });
      fs.copyFileSync(mockPath, path.join(dest, `pkcs11-mock${ext}`));
    } else {
      // Linux: modutil -add
      execSync(`modutil -add "OpenCert" -libfile "${mockPath}" -dbdir sql:$HOME/.pki/nssdb -force`, { stdio: 'ignore' });
    }
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message || '注册失败，可能需要管理员权限' };
  }
});

// ---- IPC：重启后端 ----
ipcMain.handle('restart-backend', async () => {
  await stopBackend();
  backendProcess = spawnBackend();
  if (backendProcess) {
    const ok = await waitForBackend();
    backendReady = ok;
    updateTrayStatus(ok);
    return { success: ok };
  }
  return { success: false, error: '后端可执行文件未找到' };
});

// ---- 单实例锁定 ----
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });

  app.whenReady().then(async () => {
    createTray();

    // 尝试启动后端
    const binPath = getBackendPath();
    if (binPath) {
      backendProcess = spawnBackend();
      const ok = await waitForBackend(1026, 10000);
      backendReady = ok;
      updateTrayStatus(ok);
      if (!ok) {
        console.warn('[Electron] 后端未在 10 秒内就绪，仍加载前端');
      }
    } else {
      console.warn('[Electron] 未找到 client-card 可执行文件，仅启动前端');
      // 弹窗提示
      dialog.showMessageBoxSync({
        type: 'warning',
        title: 'OpenCert Manager',
        message: '未找到后端程序 client-card',
        detail: '请确保 client-card 可执行文件与应用位于同一目录。部分功能将不可用。',
      });
    }

    createWindow();
  });
}

app.on('window-all-closed', () => {
  // macOS 上保持应用运行（托盘）
  if (process.platform !== 'darwin') {
    // 不退出，保持托盘
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  } else {
    mainWindow.show();
  }
});

app.on('before-quit', async () => {
  isQuitting = true;
  await stopBackend();
});