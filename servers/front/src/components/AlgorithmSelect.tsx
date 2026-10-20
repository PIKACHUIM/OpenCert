import React, { useEffect, useMemo, useState } from 'react';
import { Select } from 'antd';
import { getMetaAlgorithms } from '../api';
import type { AlgorithmCatalog } from '../types';

/**
 * 密钥算法选择器。
 *
 * 选项来自 /api/meta/algorithms（不再各页面写死），支持两种用法：
 *  - allowed：只展示业务允许的算法（颁发模板 / 商品规格限制）；
 *  - family：只展示某一族（如 sm2 或 ec），用于签名算法联动。
 */
export interface AlgorithmSelectProps {
  value?: string;
  onChange?: (value: string) => void;
  /** 仅允许的算法（为空不限制） */
  allowed?: string[];
  /** 仅展示某个族：rsa / ec / sm2 / ed25519 */
  family?: string;
  placeholder?: string;
  disabled?: boolean;
  style?: React.CSSProperties;
}

const familyOf = (name: string): string => {
  const n = (name || '').toLowerCase();
  if (n.startsWith('rsa')) return 'rsa';
  if (n.startsWith('sm2')) return 'sm2';
  if (n.startsWith('ed25519')) return 'ed25519';
  if (n.startsWith('ec') || n.startsWith('brainpool')) return 'ec';
  return '';
};

const AlgorithmSelect: React.FC<AlgorithmSelectProps> = ({
  value,
  onChange,
  allowed,
  family,
  placeholder = '请选择密钥算法',
  disabled,
  style,
}) => {
  const [catalog, setCatalog] = useState<AlgorithmCatalog | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    getMetaAlgorithms()
      .then((c) => { if (alive) setCatalog(c); })
      .catch(() => { if (alive) setCatalog({ algorithms: [], signature_algorithms: [], key_type_to_sig_hashes: {} }); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);

  const options = useMemo(() => {
    const keys = (catalog?.algorithms ?? []).filter((a) => a.category === 'key');
    return keys
      .filter((a) => a.available)
      .filter((a) => (allowed && allowed.length > 0 ? allowed.includes(a.name) : true))
      .filter((a) => (family ? familyOf(a.name) === family : true))
      .map((a) => ({
        value: a.name,
        label: a.deprecated ? `${a.display}（不推荐）` : a.display,
        disabled: a.deprecated,
      }));
  }, [catalog, allowed, family]);

  return (
    <Select
      value={value}
      onChange={onChange}
      options={options}
      placeholder={placeholder}
      disabled={disabled}
      loading={loading}
      style={style}
      showSearch
      optionFilterProp="label"
    />
  );
};

export default AlgorithmSelect;
