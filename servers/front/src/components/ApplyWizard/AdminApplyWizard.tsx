import React, { useEffect, useState } from 'react';
import { Alert, Button, Card, Divider, Drawer, Empty, Form, Input, Select, Space, Switch, message } from 'antd';
import { UserAddOutlined } from '@ant-design/icons';
import { listAdminApplyUsers, getAdminApplyContext, adminCreateCertApplication } from '../../api';
import type { AdminApplyContext, DeliveryMode, User } from '../../types';
import AlgorithmSelect from '../AlgorithmSelect';

const DELIVERY_LABELS: Record<string, string> = {
  download: '文件下载', cloud_card: '云端智能卡', csr: '自备 CSR',
  physical_card: '实体智能卡（CSR）', virtual_card: '本地虚拟卡（CSR）',
};
const CSR_DELIVERY_MODES = new Set(['csr', 'physical_card', 'virtual_card']);

/** 代办申请抽屉：选客户 → 选来源 → 选/填资料 → 提交 */
const AdminApplyWizard: React.FC<{
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}> = ({ open, onClose, onDone }) => {
  const [users, setUsers] = useState<Array<Pick<User, 'uuid' | 'username' | 'email'>>>([]);
  const [userUUID, setUserUUID] = useState<string>('');
  const [ctx, setCtx] = useState<AdminApplyContext | null>(null);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form] = Form.useForm();

  useEffect(() => {
    if (!open) return;
    listAdminApplyUsers({ page: 1, page_size: 100 })
      .then((r) => setUsers(r.items))
      .catch((err: any) => {
        setUsers([]);
        message.error(err.message || '加载客户列表失败');
      });
  }, [open]);

  useEffect(() => {
    if (!userUUID) { setCtx(null); return; }
    setLoading(true);
    getAdminApplyContext(userUUID)
      .then((data) => {
        setCtx(data);
        // 默认选中第一个可代办类型
        const first = data.templates?.[0]?.uuid;
        if (first) form.setFieldValue('cert_apply_tmpl_uuid', first);
      })
      .catch((err) => message.error(err.message))
      .finally(() => setLoading(false));
  }, [userUUID, form]);

  const mode = Form.useWatch('mode', form);
  const subscriptionUUID = Form.useWatch('subscription_uuid', form) as string | undefined;
  const subjectMode = Form.useWatch('subject_mode', form);
  const extMode = Form.useWatch('ext_mode', form);
  const orderNo = Form.useWatch('order_no', form) as string | undefined;
  const applyTemplateUUID = Form.useWatch('cert_apply_tmpl_uuid', form) as string | undefined;
  const selectedDeliveryMode = Form.useWatch('delivery_mode', form) as DeliveryMode | undefined;
  const selectedOrder = ctx?.orders.find((order) => order.order_no === orderNo);
  const selectedTemplate = ctx?.templates.find((template) => template.uuid === applyTemplateUUID);
  const deliveryModes = mode === 'order'
    ? (selectedOrder?.delivery_mode ? [selectedOrder.delivery_mode] : [])
    : selectedTemplate?.delivery_modes ?? [];
  const deliveryMode = mode === 'order' ? selectedOrder?.delivery_mode || undefined : selectedDeliveryMode;
  const needsCSR = CSR_DELIVERY_MODES.has(deliveryMode ?? '');
  const localCardDelivery = deliveryMode === 'physical_card' || deliveryMode === 'virtual_card';
  const deliveryModesKey = deliveryModes.join('|');
  const selectedSubscription = ctx?.subscriptions.find((subscription) => subscription.uuid === subscriptionUUID);
  const subscriptionTemplates = ctx?.templates.filter((template) =>
    template.apply_modes.includes('subscription') &&
    selectedSubscription?.items.some((item) => item.cert_apply_tmpl_uuid === template.uuid),
  ) ?? [];

  useEffect(() => {
    if (!subscriptionUUID || !ctx) return;
    const subscription = ctx.subscriptions.find((item) => item.uuid === subscriptionUUID);
    const eligible = ctx.templates.filter((template) =>
      template.apply_modes.includes('subscription') &&
      subscription?.items.some((item) => item.cert_apply_tmpl_uuid === template.uuid),
    );
    const current = form.getFieldValue('cert_apply_tmpl_uuid');
    if (!eligible.some((template) => template.uuid === current)) {
      form.setFieldValue('cert_apply_tmpl_uuid', eligible[0]?.uuid);
    }
  }, [subscriptionUUID, ctx, form]);

  useEffect(() => {
    form.setFieldValue('csr_pem', '');
    if (mode === 'order' && selectedOrder?.delivery_mode) {
      form.setFieldValue('delivery_mode', undefined);
      return;
    }
    if (deliveryModes.length === 0) {
      form.setFieldValue('delivery_mode', undefined);
      return;
    }
    if (!deliveryModes.includes(form.getFieldValue('delivery_mode'))) {
      form.setFieldValue('delivery_mode', deliveryModes[0]);
    }
  }, [userUUID, mode, orderNo, applyTemplateUUID, deliveryModesKey, selectedOrder?.delivery_mode, form]);

  const handleSubmit = async () => {
    if (!userUUID) { message.warning('请先选择客户'); return; }
    try {
      const values = await form.validateFields();
      if (!deliveryMode) {
        message.warning('请先选择或确认交付目标');
        return;
      }
      if (needsCSR && !values.csr_pem?.trim()) {
        message.warning('该交付目标需要设备生成的 CSR');
        return;
      }
      if (deliveryMode === 'cloud_card' && !values.card_uuid) {
        message.warning('请为云端智能卡证书选择目标卡片');
        return;
      }
      setSubmitting(true);
      const payload: any = {
        user_uuid: userUUID,
        skip_approval: !!values.skip_approval,
        key_type: values.key_type || '',
        delivery_mode: deliveryMode,
        csr_pem: needsCSR ? values.csr_pem.trim() : '',
        card_uuid: deliveryMode === 'cloud_card' ? values.card_uuid : undefined,
      };
      if (values.mode === 'order') payload.order_no = values.order_no;
      else if (values.mode === 'subscription') {
        payload.subscription_uuid = values.subscription_uuid;
        payload.cert_apply_tmpl_uuid = values.cert_apply_tmpl_uuid;
      } else payload.cert_apply_tmpl_uuid = values.cert_apply_tmpl_uuid;

      if (values.subject_mode === 'existing') {
        payload.subject_info_uuid = values.subject_info_uuid;
      } else if (values.subject_mode === 'input') {
        payload.subject = {};
        ['CN', 'O', 'OU', 'C'].forEach((k) => {
          if (values[`subject_${k}`]) payload.subject[k] = values[`subject_${k}`];
        });
      }
      if (values.ext_mode === 'existing') {
        payload.extension_info_uuids = values.extension_info_uuids || [];
      } else if (values.ext_mode === 'input' && values.ext_value) {
        payload.extensions = [{ info_type: values.ext_type, value: values.ext_value }];
      }

      const res = await adminCreateCertApplication(payload);
      message.success(res?.message || '申请已提交');
      form.resetFields();
      setCtx(null);
      setUserUUID('');
      onDone();
      onClose();
    } catch (err: any) {
      if (err?.errorFields) return; // 表单校验失败
      message.error(err.message || '提交失败');
    } finally { setSubmitting(false); }
  };

  return (
    <Drawer
      title={<Space><UserAddOutlined />新增申请（代客户提交）</Space>}
      width={720} open={open} onClose={onClose} destroyOnClose
      extra={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={submitting} onClick={handleSubmit}>提交申请</Button>
        </Space>
      }
    >
      <Form form={form} layout="vertical" initialValues={{
        mode: 'template', subject_mode: 'existing', ext_mode: 'existing', skip_approval: false,
      }}>
        <Form.Item label="客户" required>
          <Select
            showSearch optionFilterProp="label"
            placeholder="搜索并选择要代办的客户"
            value={userUUID || undefined}
            onChange={(v) => setUserUUID(v)}
            options={users.map((u) => ({
              value: u.uuid,
              label: `${u.username}${u.email ? `（${u.email}）` : ''}`,
            }))}
          />
        </Form.Item>

        {loading && <Card loading size="small" />}

        {ctx && (
          <>
            <Form.Item label="申请来源" name="mode">
              <Select
                options={[
                  { value: 'order', label: '该客户的已支付订单' },
                  { value: 'template', label: '直接按证书类型申请' },
                  ...(ctx.subscriptions.some((s) => s.active && s.items.length > 0)
                    ? [{ value: 'subscription', label: '使用订阅额度' }]
                    : []),
                ]}
              />
            </Form.Item>

            {mode === 'order' && (
              <Form.Item label="订单" name="order_no" rules={[{ required: true, message: '请选择订单' }]}>
                <Select
                  placeholder={ctx.orders.length ? '选择订单' : '该客户没有可用的证书订单'}
                  options={ctx.orders.map((o) => ({
                    value: o.order_no,
                    label: `${o.order_no}｜${o.template_name || '证书'}｜${o.status}`,
                  }))}
                />
              </Form.Item>
            )}
            {mode === 'template' && (
              <Form.Item label="证书类型" name="cert_apply_tmpl_uuid" rules={[{ required: true, message: '请选择证书类型' }]}>
                <Select
                  options={ctx.templates.map((t) => ({
                    value: t.uuid,
                    label: `${t.name}${t.require_approval ? '（需审批）' : '（自动签发）'}`,
                  }))}
                />
              </Form.Item>
            )}
            {mode === 'subscription' && (
              <>
                <Form.Item label="订阅" name="subscription_uuid" rules={[{ required: true, message: '请选择订阅' }]}>
                  <Select
                    options={ctx.subscriptions.filter((s) => s.active).map((s) => ({ value: s.uuid, label: s.plan_name }))}
                  />
                </Form.Item>
                <Form.Item label="订阅内的证书类型" name="cert_apply_tmpl_uuid" rules={[{ required: true, message: '请选择证书类型' }]}>
                  <Select
                    placeholder={subscriptionTemplates.length ? '选择要消耗额度的证书类型' : '该订阅未包含可申请的证书类型'}
                    options={subscriptionTemplates.map((template) => ({
                      value: template.uuid,
                      label: `${template.name}${template.require_approval ? '（需审批）' : '（自动签发）'}`,
                    }))}
                  />
                </Form.Item>
              </>
            )}

            {mode === 'order' ? (
              selectedOrder?.delivery_mode ? (
                <Form.Item label="交付目标">
                  <Input readOnly value={DELIVERY_LABELS[selectedOrder.delivery_mode] ?? selectedOrder.delivery_mode} />
                </Form.Item>
              ) : <Alert type="warning" showIcon message="该历史订单未记录交付目标，需由运营核实订单策略后再代办。" />
            ) : (
              <Form.Item name="delivery_mode" label="交付目标" rules={[{ required: true, message: '请选择交付目标' }]}>
                <Select
                  placeholder="请选择模板允许的证书交付目标"
                  options={deliveryModes.map((delivery) => ({ value: delivery, label: DELIVERY_LABELS[delivery] ?? delivery }))}
                  onChange={() => { form.setFieldValue('csr_pem', ''); form.setFieldValue('card_uuid', undefined); }}
                />
              </Form.Item>
            )}

            {deliveryMode === 'cloud_card' && (
              <Form.Item name="card_uuid" label="签发到云端智能卡" rules={[{ required: true, message: '请选择目标云端智能卡' }]}>
                <Select
                  placeholder={ctx.cards.length ? '选择目标云端智能卡' : '客户暂无可用智能卡'}
                  options={ctx.cards.map((card) => ({ value: card.uuid, label: card.card_name }))}
                />
              </Form.Item>
            )}

            <Divider titlePlacement="start" plain>证书资料</Divider>

            <Form.Item label="主体信息" name="subject_mode">
              <Select
                options={[
                  { value: 'existing', label: '使用客户已通过的主体信息' },
                  { value: 'input', label: '由我直接录入并核定' },
                ]}
              />
            </Form.Item>
            {subjectMode === 'existing' ? (
              <Form.Item label="选择主体信息" name="subject_info_uuid">
                <Select
                  allowClear placeholder={ctx.subject_infos.length ? '选择已通过的主体信息' : '客户暂无已通过的主体信息'}
                  options={ctx.subject_infos.map((s) => ({
                    value: s.uuid,
                    label: Object.entries(s.fields ?? {}).map(([k, v]) => `${k}=${v}`).join(', ') || s.uuid.slice(0, 8),
                  }))}
                />
              </Form.Item>
            ) : (
              <Space style={{ width: '100%' }} size={12} wrap>
                <Form.Item label="CN（通用名称）" name="subject_CN" rules={[{ required: true, message: '请填写 CN' }]}>
                  <Input placeholder="example.com" style={{ width: 220 }} />
                </Form.Item>
                <Form.Item label="组织 O" name="subject_O"><Input style={{ width: 180 }} /></Form.Item>
                <Form.Item label="部门 OU" name="subject_OU"><Input style={{ width: 160 }} /></Form.Item>
                <Form.Item label="国家 C" name="subject_C"><Input maxLength={2} style={{ width: 100 }} placeholder="CN" /></Form.Item>
              </Space>
            )}

            <Form.Item label="扩展信息（域名 / 邮箱 / IP）" name="ext_mode">
              <Select
                options={[
                  { value: 'existing', label: '使用客户已验证的扩展信息' },
                  { value: 'input', label: '由我直接录入并核定' },
                  { value: 'none', label: '不添加（仅用主体信息）' },
                ]}
              />
            </Form.Item>
            {extMode === 'existing' && (
              <Form.Item label="选择扩展信息" name="extension_info_uuids">
                <Select
                  mode="multiple" allowClear
                  placeholder={ctx.extension_infos.length ? '可多选' : '客户暂无已验证的扩展信息'}
                  options={ctx.extension_infos.map((e) => ({
                    value: e.uuid, label: `${e.type}: ${e.value}`,
                  }))}
                />
              </Form.Item>
            )}
            {extMode === 'input' && (
              <Space size={12}>
                <Form.Item label="类型" name="ext_type" initialValue="domain">
                  <Select style={{ width: 120 }} options={[
                    { value: 'domain', label: '域名' },
                    { value: 'email', label: '邮箱' },
                    { value: 'ip', label: 'IP' },
                  ]} />
                </Form.Item>
                <Form.Item label="值" name="ext_value"><Input style={{ width: 300 }} placeholder="example.com" /></Form.Item>
              </Space>
            )}

            <Space size={12} style={{ width: '100%' }} align="start">
              <Form.Item label="密钥算法" name="key_type" extra="留空由服务端选择">
                <AlgorithmSelect style={{ width: 220 }} />
              </Form.Item>
              <Form.Item label="跳过审批，直接签发" name="skip_approval" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Space>

            {needsCSR && (
              <Form.Item
                label={localCardDelivery ? `${DELIVERY_LABELS[deliveryMode ?? '']} CSR` : '自带 CSR'}
                name="csr_pem"
                rules={[{ required: true, message: '该交付目标需要提交 CSR' }]}
                extra={localCardDelivery
                  ? 'CSR 必须由目标设备生成。服务端校验 CSR 与验证资料，不对硬件类型做远程认证；私钥不会上传。'
                  : '仅使用 CSR 公钥签发，私钥由客户保管。'}
              >
                <Input.TextArea rows={3} placeholder="-----BEGIN CERTIFICATE REQUEST-----" style={{ fontSize: 12 }} />
              </Form.Item>
            )}
          </>
        )}

        {!ctx && !loading && <Empty description="选择客户后加载可用的订单、订阅与资料" />}
      </Form>
    </Drawer>
  );
};

export default AdminApplyWizard;
