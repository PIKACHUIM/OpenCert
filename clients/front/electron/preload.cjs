// OpenCert Manager — Electron Preload 脚本
// 通过 contextBridge 安全暴露 IPC 通道给渲染进程
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // 注册 pkcs11-mock 到系统（需要管理员权限）
  registerPkcs11Mock: () => ipcRenderer.invoke('register-pkcs11-mock'),

  // 重启后端进程
  restartBackend: () => ipcRenderer.invoke('restart-backend'),

  // 监听后端状态变化
  onBackendDown: (callback) => {
    const handler = (_event, data) => callback(data);
    ipcRenderer.on('backend-down', handler);
    return () => ipcRenderer.removeListener('backend-down', handler);
  },

  onBackendUp: (callback) => {
    const handler = () => callback();
    ipcRenderer.on('backend-up', handler);
    return () => ipcRenderer.removeListener('backend-up', handler);
  },

  // 平台信息
  platform: process.platform,
});
