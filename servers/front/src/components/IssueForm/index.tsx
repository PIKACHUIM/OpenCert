import React from 'react';
import { Form, Input, Select, Space, DatePicker } from 'antd';
import AlgorithmSelect from '../AlgorithmSelect';

const { RangePicker } = DatePicker;

export interface IssueFormProps {
  allowedKeyTypes?: string[];
  signatureAlgorithms?: string[];
  signatureAlgorithmRequired?: boolean;
  validityHint: string;
  commonNamePlaceholder?: string;
}

const IssueForm: React.FC<IssueFormProps> = ({
  allowedKeyTypes,
  signatureAlgorithms,
  signatureAlgorithmRequired = false,
  validityHint,
  commonNamePlaceholder,
}) => (
  <>
    <Form.Item label="密钥算法" name="key_type" rules={[{ required: true, message: '请选择密钥算法' }]}>
      <AlgorithmSelect allowed={allowedKeyTypes} />
    </Form.Item>
    {(signatureAlgorithmRequired || (signatureAlgorithms && signatureAlgorithms.length > 0)) && (
      <Form.Item label="签名算法" name="sig_alg"
        rules={signatureAlgorithmRequired ? [{ required: true, message: '请选择签名算法' }] : undefined}
        extra={signatureAlgorithmRequired && !signatureAlgorithms?.length
          ? '当前 CA 与模板没有共同支持的签名算法'
          : signatureAlgorithmRequired ? undefined : '留空按签发者密钥类型自动选择'}>
        <Select allowClear={!signatureAlgorithmRequired} placeholder={signatureAlgorithmRequired ? '选择签名算法' : '自动选择'}
          disabled={signatureAlgorithmRequired && !signatureAlgorithms?.length}
          options={(signatureAlgorithms ?? []).map((algorithm) => ({ value: algorithm, label: algorithm }))} />
      </Form.Item>
    )}
    <Form.Item label="CommonName" name="common_name" rules={[{ required: true, message: '请填写 CommonName' }]}>
      <Input placeholder={commonNamePlaceholder} />
    </Form.Item>
    <Space style={{ width: '100%' }} size={12}>
      <Form.Item label="组织" name="organization" style={{ flex: 1 }}><Input /></Form.Item>
      <Form.Item label="国家代码" name="country" style={{ width: 140 }}><Input maxLength={2} placeholder="CN" /></Form.Item>
    </Space>
    <Form.Item label="生效 / 失效时间" name="validity" extra={validityHint}>
      <RangePicker showTime style={{ width: '100%' }} />
    </Form.Item>
  </>
);

export default IssueForm;
