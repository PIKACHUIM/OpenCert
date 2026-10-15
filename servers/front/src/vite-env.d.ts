/// <reference types="vite/client" />

// Vite 环境变量类型声明。
// 此前缺少该声明文件，导致 `import.meta.env` 与 CSS 资源导入在类型检查时失败。
interface ImportMetaEnv {
  /** 可选：自定义 API 基础地址（默认走同源 /api） */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
