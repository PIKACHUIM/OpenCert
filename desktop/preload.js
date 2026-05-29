// preload.js - 在渲染进程加载前执行
// 暴露安全的 API 给渲染进程

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  // 平台信息
  platform: process.platform,
  isElectron: true,

  // 窗口操作
  minimize: () => ipcRenderer.send('window:minimize'),
  maximize: () => ipcRenderer.send('window:maximize'),
  close: () => ipcRenderer.send('window:close'),

  // 版本信息
  versions: {
    node: process.versions.node,
    chrome: process.versions.chrome,
    electron: process.versions.electron,
  },
});
