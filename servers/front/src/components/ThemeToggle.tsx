import React from 'react';
import { Tooltip } from 'antd';
import { useThemeStore } from '../store/theme';

/** 太阳图标（浅色模式） */
const SunIcon: React.FC = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"
    strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <circle cx="12" cy="12" r="4.2" />
    <path d="M12 2.6v2.2M12 19.2v2.2M4.6 4.6l1.6 1.6M17.8 17.8l1.6 1.6M2.6 12h2.2M19.2 12h2.2M4.6 19.4l1.6-1.6M17.8 6.2l1.6-1.6" />
  </svg>
);

/** 月亮图标（深色模式） */
const MoonIcon: React.FC = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"
    strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="M20.4 14.2A8.4 8.4 0 1 1 9.8 3.6a6.9 6.9 0 0 0 10.6 10.6Z" />
  </svg>
);

interface ThemeToggleProps {
  /** ghost 变体用于深色背景（侧边栏/品牌区） */
  variant?: 'default' | 'ghost';
}

const ThemeToggle: React.FC<ThemeToggleProps> = ({ variant = 'default' }) => {
  const { darkMode, toggleDarkMode } = useThemeStore();
  return (
    <Tooltip title={darkMode ? '切换到浅色模式' : '切换到深色模式'}>
      <button
        type="button"
        className={`oc-theme-toggle${variant === 'ghost' ? ' oc-theme-toggle--ghost' : ''}`}
        onClick={toggleDarkMode}
        aria-label={darkMode ? '切换到浅色模式' : '切换到深色模式'}
      >
        {darkMode ? <MoonIcon /> : <SunIcon />}
      </button>
    </Tooltip>
  );
};

export default ThemeToggle;
