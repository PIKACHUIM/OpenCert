import React from 'react';
import { Typography } from 'antd';

const { Title, Paragraph, Text } = Typography;

/**
 * 轻量 Markdown 渲染器（帮助文档专用）。
 *
 * 只支持文档实际用到的语法：标题、段落、粗体、行内代码、链接、
 * 有序/无序/任务列表、引用、代码块、表格、分隔线。
 * 全部输出为 React 元素，不使用 dangerouslySetInnerHTML，杜绝 XSS。
 */

type Block =
  | { kind: 'heading'; level: number; text: string }
  | { kind: 'paragraph'; text: string }
  | { kind: 'code'; lang: string; text: string }
  | { kind: 'quote'; text: string }
  | { kind: 'list'; ordered: boolean; items: { text: string; checked?: boolean }[] }
  | { kind: 'table'; header: string[]; rows: string[][] }
  | { kind: 'hr' };

const splitRow = (line: string) =>
  line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());

/** 把 Markdown 文本切分为块 */
const parseBlocks = (src: string): Block[] => {
  const lines = src.replace(/\r\n/g, '\n').split('\n');
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === '') { i++; continue; }

    // 代码块
    const fence = line.match(/^```(\w*)/);
    if (fence) {
      const buf: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith('```')) { buf.push(lines[i]); i++; }
      i++;
      blocks.push({ kind: 'code', lang: fence[1], text: buf.join('\n') });
      continue;
    }

    // 标题
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { blocks.push({ kind: 'heading', level: h[1].length, text: h[2] }); i++; continue; }

    // 分隔线
    if (/^(-{3,}|\*{3,})$/.test(line.trim())) { blocks.push({ kind: 'hr' }); i++; continue; }

    // 表格（第二行为分隔行）
    if (line.trim().startsWith('|') && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {
      const header = splitRow(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].trim().startsWith('|')) { rows.push(splitRow(lines[i])); i++; }
      blocks.push({ kind: 'table', header, rows });
      continue;
    }

    // 引用
    if (line.startsWith('>')) {
      const buf: string[] = [];
      while (i < lines.length && lines[i].startsWith('>')) { buf.push(lines[i].replace(/^>\s?/, '')); i++; }
      blocks.push({ kind: 'quote', text: buf.join(' ') });
      continue;
    }

    // 列表
    const li = line.match(/^\s*([-*]|\d+\.)\s+(.*)$/);
    if (li) {
      const ordered = /\d+\./.test(li[1]);
      const items: { text: string; checked?: boolean }[] = [];
      while (i < lines.length) {
        const m = lines[i].match(/^\s*([-*]|\d+\.)\s+(.*)$/);
        if (m) {
          const task = m[2].match(/^\[( |x)\]\s+(.*)$/i);
          items.push(task ? { text: task[2], checked: task[1].toLowerCase() === 'x' } : { text: m[2] });
          i++;
        } else if (lines[i].match(/^\s{2,}\S/) && items.length) {
          // 列表项的缩进续行
          items[items.length - 1].text += ' ' + lines[i].trim();
          i++;
        } else {
          break;
        }
      }
      blocks.push({ kind: 'list', ordered, items });
      continue;
    }

    // 段落：合并连续非空行
    const buf: string[] = [line];
    i++;
    while (i < lines.length && lines[i].trim() !== '' &&
      !/^(#{1,4}\s|```|>|\s*([-*]|\d+\.)\s|\|)/.test(lines[i])) {
      buf.push(lines[i]);
      i++;
    }
    blocks.push({ kind: 'paragraph', text: buf.join(' ') });
  }
  return blocks;
};

/** 渲染行内语法：**粗体**、`代码`、[链接](url) */
const renderInline = (text: string, keyPrefix: string): React.ReactNode[] => {
  const nodes: React.ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    const key = `${keyPrefix}-${n++}`;
    if (tok.startsWith('**')) {
      nodes.push(<Text strong key={key}>{tok.slice(2, -2)}</Text>);
    } else if (tok.startsWith('`')) {
      nodes.push(<Text code key={key}>{tok.slice(1, -1)}</Text>);
    } else {
      const lm = tok.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
      const href = lm?.[2] ?? '';
      // 仅允许 http(s) 与站内相对地址，拒绝 javascript: 等协议
      const safe = /^(https?:\/\/|\/)/.test(href);
      nodes.push(safe
        ? <a key={key} href={href} target={href.startsWith('/') ? undefined : '_blank'} rel="noreferrer">{lm?.[1]}</a>
        : <span key={key}>{lm?.[1]}</span>);
    }
    last = m.index + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
};

/** 生成标题锚点 */
export const headingId = (text: string) =>
  'h-' + text.replace(/[^\w\u4e00-\u9fa5]+/g, '-').replace(/^-|-$/g, '').toLowerCase();

const Markdown: React.FC<{ source: string }> = ({ source }) => {
  const blocks = parseBlocks(source);

  return (
    <div className="oc-markdown" style={{ fontSize: 14, lineHeight: 1.85, color: '#1f2937' }}>
      {blocks.map((b, idx) => {
        const key = `b-${idx}`;
        switch (b.kind) {
          case 'heading': {
            const level = Math.min(b.level + 1, 5) as 2 | 3 | 4 | 5;
            return (
              <Title key={key} id={headingId(b.text)} level={level}
                style={{ marginTop: b.level === 1 ? 0 : 28, marginBottom: 12 }}>
                {renderInline(b.text, key)}
              </Title>
            );
          }
          case 'paragraph':
            return <Paragraph key={key} style={{ marginBottom: 12 }}>{renderInline(b.text, key)}</Paragraph>;
          case 'quote':
            return (
              <div key={key} style={{
                borderLeft: '3px solid #1d4ed8', background: '#f5f8ff',
                padding: '10px 14px', borderRadius: 6, margin: '12px 0', color: '#374151',
              }}>
                {renderInline(b.text, key)}
              </div>
            );
          case 'code':
            return (
              <pre key={key} style={{
                background: '#0f172a', color: '#e2e8f0', padding: '14px 16px', borderRadius: 8,
                overflowX: 'auto', fontSize: 12.5, lineHeight: 1.7, margin: '12px 0',
              }}>
                <code>{b.text}</code>
              </pre>
            );
          case 'hr':
            return <hr key={key} style={{ border: 0, borderTop: '1px solid #e5e7eb', margin: '20px 0' }} />;
          case 'list': {
            const Tag = b.ordered ? 'ol' : 'ul';
            const isTask = b.items.some((it) => it.checked !== undefined);
            return (
              <Tag key={key} style={{ paddingLeft: isTask ? 4 : 22, margin: '8px 0 14px', listStyle: isTask ? 'none' : undefined }}>
                {b.items.map((it, j) => (
                  <li key={`${key}-${j}`} style={{ marginBottom: 4 }}>
                    {it.checked !== undefined && (
                      <input type="checkbox" checked={it.checked} readOnly style={{ marginRight: 8 }} />
                    )}
                    {renderInline(it.text, `${key}-${j}`)}
                  </li>
                ))}
              </Tag>
            );
          }
          case 'table':
            return (
              <div key={key} style={{ overflowX: 'auto', margin: '12px 0 16px' }}>
                <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: 13 }}>
                  <thead>
                    <tr>
                      {b.header.map((h, j) => (
                        <th key={j} style={{
                          textAlign: 'left', padding: '8px 12px', background: '#f8fafc',
                          borderBottom: '1px solid #e5e7eb', fontWeight: 600, whiteSpace: 'nowrap',
                        }}>{renderInline(h, `${key}-h${j}`)}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {b.rows.map((row, r) => (
                      <tr key={r}>
                        {row.map((c, j) => (
                          <td key={j} style={{ padding: '8px 12px', borderBottom: '1px solid #f1f5f9', verticalAlign: 'top' }}>
                            {renderInline(c, `${key}-${r}-${j}`)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          default:
            return null;
        }
      })}
    </div>
  );
};

export default Markdown;
