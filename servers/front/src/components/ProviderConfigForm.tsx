import React, { useEffect, useMemo } from 'react';
import { Form, Input, InputNumber, Select, Divider, Typography } from 'antd';
import type { VerifyProviderDriver, VerifyProviderDriverField } from '../types';

/**
 * 认证接口配置表单：按驱动描述动态渲染字段。
 *
 * 关键点：驱动与类型必须用 Form.useWatch 订阅，不能只在渲染时读一次——
 * 否则切换驱动后新驱动的字段不会出现（这是旧页面"配置项不显示"的根因）。
 */
export interface ProviderConfigFormProps {
  drivers: VerifyProviderDriver[];
  /** 当前类型：email / domain / identity */
  kind?: string;
  disabled?: boolean;
}

const { Text } = Typography;

const renderField = (field: VerifyProviderDriverField, disabled?: boolean) => {
  const rules = field.required ? [{ required: true, message: `请填写${field.label}` }] : undefined;
  let control: React.ReactNode;

  switch (field.type) {
    case 'select':
      control = (
        <Select
          placeholder={field.placeholder || `请选择${field.label}`}
          options={(field.options ?? []).map((o) => ({ value: o, label: o }))}
          disabled={disabled}
          allowClear
        />
      );
      break;
    case 'textarea':
      control = (
        <Input.TextArea
          rows={3}
          placeholder={field.placeholder}
          disabled={disabled}
          style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 12 }}
        />
      );
      break;
    case 'number':
      control = <InputNumber style={{ width: '100%' }} placeholder={field.placeholder} disabled={disabled} />;
      break;
    case 'password':
      control = <Input.Password placeholder={field.placeholder} disabled={disabled} autoComplete="new-password" />;
      break;
    default:
      control = <Input placeholder={field.placeholder} disabled={disabled} />;
  }

  return (
    <Form.Item
      key={field.key}
      name={['config', field.key]}
      label={field.label}
      rules={rules}
      extra={field.help ? <Text type="secondary" style={{ fontSize: 12 }}>{field.help}</Text> : undefined}
    >
      {control}
    </Form.Item>
  );
};

const ProviderConfigForm: React.FC<ProviderConfigFormProps> = ({ drivers, kind, disabled }) => {
  const form = Form.useFormInstance();
  // 订阅驱动变化：驱动切换后必须重新渲染字段（Form.useWatch 触发重算）
  const driver = Form.useWatch('driver', form);
  const watchedKind = Form.useWatch('kind', form);

  const current = useMemo(
    () => drivers.find((d) => d.driver === driver && (!watchedKind || d.kind === watchedKind)),
    [drivers, driver, watchedKind],
  );

  // 新建时按驱动默认值预填（仅填未设置的项，不覆盖用户已输入内容）
  useEffect(() => {
    if (!current) return;
    const values = (form.getFieldValue('config') ?? {}) as Record<string, string>;
    let changed = false;
    const next = { ...values };
    current.fields.forEach((f) => {
      if (f.default && (next[f.key] === undefined || next[f.key] === '')) {
        next[f.key] = f.default;
        changed = true;
      }
    });
    if (changed) form.setFieldValue('config', next);
  }, [current, form]);

  if (!current) {
    return <Text type="secondary">请选择接口类型与驱动</Text>;
  }

  // 按 group 分组渲染（无 group 的归入默认组）
  const groups = new Map<string, VerifyProviderDriverField[]>();
  current.fields.forEach((f) => {
    const g = f.group || '';
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g)!.push(f);
  });

  return (
    <div>
      {current.description && (
        <Text type="secondary" style={{ display: 'block', marginBottom: 12 }}>{current.description}</Text>
      )}
      {Array.from(groups.entries()).map(([group, fields]) => (
        <div key={group || 'default'}>
          {group && <Divider titlePlacement="start" plain style={{ margin: '8px 0 12px' }}>{group}</Divider>}
          {fields.map((f) => renderField(f, disabled))}
        </div>
      ))}
      {kind === 'identity' && driver === 'callback' && (
        <Text type="secondary" style={{ fontSize: 12 }}>
          回调地址由平台自动生成：保存后可在列表中复制，填到实名服务的回调配置里。
        </Text>
      )}
    </div>
  );
};

export default ProviderConfigForm;
