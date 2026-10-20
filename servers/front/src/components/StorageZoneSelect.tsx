import React, { useEffect, useState } from 'react';
import { Select, Tag } from 'antd';
import { listStorageZones } from '../api';
import type { StorageZone } from '../types';

/**
 * 存储区域选择器：签发证书 / 创建 CA / 密钥存储模板共用。
 *
 * 只展示启用中的区域；硬件区域（TPM/HSM）额外提示"私钥不可导出"，
 * 便于管理员在选择时就知道该区域不能提供文件下载。
 */
export interface StorageZoneSelectProps {
  value?: string;
  onChange?: (value: string) => void;
  /** 是否允许空（使用默认区域） */
  allowEmpty?: boolean;
  placeholder?: string;
  disabled?: boolean;
  style?: React.CSSProperties;
}

export const isHardwareZone = (zone?: StorageZone | null): boolean =>
  !!zone && (zone.storage_type === 'hsm' || zone.storage_type === 'tpm');

const zoneTypeLabel: Record<string, string> = {
  database: '本地加密',
  hsm: 'HSM',
  tpm: 'TPM',
};

const StorageZoneSelect: React.FC<StorageZoneSelectProps> = ({
  value,
  onChange,
  allowEmpty = true,
  placeholder = '默认（本地加密存储）',
  disabled,
  style,
}) => {
  const [zones, setZones] = useState<StorageZone[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    listStorageZones()
      .then((items) => { if (alive) setZones(items.filter((z) => z.status !== 'disabled')); })
      .catch(() => { if (alive) setZones([]); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);

  const options = zones.map((z) => {
    const hardware = isHardwareZone(z);
    return {
      value: z.uuid,
      label: (
        <span>
          {z.name}
          <Tag style={{ marginLeft: 8 }} color={hardware ? 'orange' : 'blue'}>
            {zoneTypeLabel[z.storage_type] || z.storage_type}
          </Tag>
          {hardware && <span style={{ color: '#999', fontSize: 12 }}>私钥不可导出</span>}
        </span>
      ),
    };
  });

  return (
    <Select
      value={value || undefined}
      onChange={(v) => onChange?.(v ?? '')}
      options={options}
      placeholder={placeholder}
      disabled={disabled}
      loading={loading}
      style={style}
      allowClear={allowEmpty}
    />
  );
};

export default StorageZoneSelect;
