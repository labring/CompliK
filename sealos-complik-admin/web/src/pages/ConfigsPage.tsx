import { useMemo, useState } from "react";
import {
  Button,
  ConfirmModal,
  DetailList,
  Drawer,
  EmptyState,
  Field,
  Input,
  Modal,
  PageHeader,
  SurfaceCard,
  TextArea,
} from "../components/ui";
import { useAppData } from "../contexts/AppDataContext";
import type { ConfigRecord, CreateConfigInput } from "../types";

type ImportConfigRecord = {
  config_name?: unknown;
  configName?: unknown;
  config_type?: unknown;
  configType?: unknown;
  config_value?: unknown;
  configValue?: unknown;
  description?: unknown;
};

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(record: Record<string, unknown>, key: string) {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function readRequiredString(value: unknown, field: string, index: number) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`第 ${index + 1} 条配置缺少 ${field}。`);
  }
  return value.trim();
}

function normalizeImportedConfig(value: unknown, index: number): CreateConfigInput {
  if (!isObjectRecord(value)) {
    throw new Error(`第 ${index + 1} 条配置必须是 JSON 对象。`);
  }

  const item = value as ImportConfigRecord;
  const configName = readRequiredString(item.config_name ?? item.configName, "config_name", index);
  const configType = readRequiredString(item.config_type ?? item.configType, "config_type", index);
  const description = typeof item.description === "string" ? item.description.trim() : "";

  const hasSnakeValue = hasOwn(value, "config_value");
  const hasCamelValue = hasOwn(value, "configValue");
  if (!hasSnakeValue && !hasCamelValue) {
    throw new Error(`第 ${index + 1} 条配置缺少 config_value。`);
  }

  return {
    configName,
    configType,
    description,
    value: JSON.stringify(hasSnakeValue ? item.config_value : item.configValue, null, 2),
  };
}

function parseImportedConfigs(source: string): CreateConfigInput[] {
  if (source.trim() === "") {
    throw new Error("请粘贴要导入的 JSON。");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error("导入 JSON 格式不正确，请检查后再提交。");
  }

  const items = Array.isArray(parsed) ? parsed : [parsed];
  if (items.length === 0) {
    throw new Error("导入 JSON 数组不能为空。");
  }

  return items.map((item, index) => normalizeImportedConfig(item, index));
}

export function ConfigsPage() {
  const { configRecords, createConfigRecord, updateConfigRecord, deleteConfigRecord } = useAppData();
  const [selected, setSelected] = useState<ConfigRecord | null>(null);
  const [open, setOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [nameKeyword, setNameKeyword] = useState("");
  const [pendingDelete, setPendingDelete] = useState<ConfigRecord | null>(null);
  const [configName, setConfigName] = useState("");
  const [configType, setConfigType] = useState("");
  const [description, setDescription] = useState("");
  const [value, setValue] = useState('{\n  "enabled": true,\n  "threshold": 3\n}');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [editConfigName, setEditConfigName] = useState("");
  const [editConfigType, setEditConfigType] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editValue, setEditValue] = useState('{\n  "enabled": true,\n  "threshold": 3\n}');
  const [editSubmitting, setEditSubmitting] = useState(false);
  const [editError, setEditError] = useState<string | null>(null);
  const [importValue, setImportValue] = useState("");
  const [importSubmitting, setImportSubmitting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  const rows = useMemo(() => {
    return configRecords.filter((item) => {
      if (nameKeyword && !item.configName.toLowerCase().includes(nameKeyword.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [configRecords, nameKeyword]);

  const handleCreateConfig = async () => {
    if (!configName.trim() || !configType.trim() || !value.trim()) {
      setFormError("配置名、配置类型和 JSON 内容均为必填。");
      return;
    }

    try {
      JSON.parse(value);
    } catch {
      setFormError("JSON 内容格式不正确，请检查后再提交。");
      return;
    }

    setSubmitting(true);
    setFormError(null);
    try {
      await createConfigRecord({
        configName: configName.trim(),
        configType: configType.trim(),
        description: description.trim(),
        value: value.trim(),
      });
      setOpen(false);
      setConfigName("");
      setConfigType("");
      setDescription("");
      setValue('{\n  "enabled": true,\n  "threshold": 3\n}');
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "新增配置失败");
    } finally {
      setSubmitting(false);
    }
  };

  const formatCreateJson = () => {
    if (!value.trim()) {
      setFormError("JSON 内容不能为空。");
      return;
    }
    try {
      const parsed = JSON.parse(value);
      setValue(JSON.stringify(parsed, null, 2));
      setFormError(null);
    } catch {
      setFormError("JSON 内容格式不正确，无法格式化。");
    }
  };

  const formatImportJson = () => {
    if (!importValue.trim()) {
      setImportError("导入 JSON 不能为空。");
      return;
    }
    try {
      const parsed = JSON.parse(importValue);
      setImportValue(JSON.stringify(parsed, null, 2));
      setImportError(null);
    } catch {
      setImportError("导入 JSON 格式不正确，无法格式化。");
    }
  };

  const handleImportConfigs = async () => {
    let configs: CreateConfigInput[];
    try {
      configs = parseImportedConfigs(importValue);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "导入 JSON 格式不正确。");
      return;
    }

    setImportSubmitting(true);
    setImportError(null);
    try {
      for (let index = 0; index < configs.length; index += 1) {
        try {
          await createConfigRecord(configs[index]);
        } catch (err) {
          const message = err instanceof Error ? err.message : "导入配置失败";
          throw new Error(`已导入 ${index} 条，第 ${index + 1} 条失败：${message}`);
        }
      }
      setImportOpen(false);
      setImportValue("");
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "导入配置失败");
    } finally {
      setImportSubmitting(false);
    }
  };

  const openEditModal = (record: ConfigRecord) => {
    setEditConfigName(record.configName);
    setEditConfigType(record.configType);
    setEditDescription(record.description);
    setEditValue(record.value);
    setEditError(null);
    setEditOpen(true);
  };

  const handleUpdateConfig = async () => {
    if (!selected) return;

    if (!editConfigName.trim() || !editConfigType.trim() || !editValue.trim()) {
      setEditError("配置名、配置类型和 JSON 内容均为必填。");
      return;
    }

    try {
      JSON.parse(editValue);
    } catch {
      setEditError("JSON 内容格式不正确，请检查后再提交。");
      return;
    }

    setEditSubmitting(true);
    setEditError(null);
    try {
      await updateConfigRecord(selected.configName, {
        configName: editConfigName.trim(),
        configType: editConfigType.trim(),
        description: editDescription.trim(),
        value: editValue.trim(),
      });
      setSelected((prev) =>
        prev
          ? {
              ...prev,
              configName: editConfigName.trim(),
              configType: editConfigType.trim(),
              description: editDescription.trim(),
              value: editValue.trim(),
            }
          : prev,
      );
      setEditOpen(false);
    } catch (err) {
      setEditError(err instanceof Error ? err.message : "修改配置失败");
    } finally {
      setEditSubmitting(false);
    }
  };

  const formatEditJson = () => {
    if (!editValue.trim()) {
      setEditError("JSON 内容不能为空。");
      return;
    }
    try {
      const parsed = JSON.parse(editValue);
      setEditValue(JSON.stringify(parsed, null, 2));
      setEditError(null);
    } catch {
      setEditError("JSON 内容格式不正确，无法格式化。");
    }
  };

  return (
    <div className="page-container">
      <PageHeader
        kicker="Configs"
        title="项目配置"
        description="统一查看配置名、描述和 JSON 内容，新增和编辑保持同一套表单结构。"
        actions={
          <>
            <Button variant="secondary" onClick={() => setImportOpen(true)}>
              导入 JSON
            </Button>
            <Button variant="primary" onClick={() => setOpen(true)}>
              新增配置
            </Button>
          </>
        }
      />

      <SurfaceCard>
        <div className="toolbar">
          <Field label="配置名搜索">
            <Input placeholder="按 config_name 搜索" value={nameKeyword} onChange={(event) => setNameKeyword(event.target.value)} />
          </Field>
        </div>
      </SurfaceCard>

      <SurfaceCard className="data-table-wrap" padded={false}>
        {rows.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>配置名</th>
                <th>描述</th>
                <th>更新时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id}>
                  <td>
                    <button className="namespace-link table-row-button" onClick={() => setSelected(item)} type="button">
                      {item.configName}
                    </button>
                  </td>
                  <td>{item.description}</td>
                  <td>{item.updatedAt}</td>
                  <td>
                    <Button variant="ghost" onClick={() => setSelected(item)}>
                      查看
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div style={{ padding: 20 }}>
            <EmptyState
              title="还没有项目配置"
              description="当前筛选条件下没有配置记录，可以新建一条配置。"
              action={<Button variant="primary" onClick={() => setOpen(true)}>新增配置</Button>}
            />
          </div>
        )}
      </SurfaceCard>

      <Drawer
        description="右侧抽屉展示配置详情，并保留足够宽度展示 JSON 内容。"
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected ? selected.configName : ""}
      >
        {selected ? (
          <>
            <DetailList
              items={[
                { label: "配置名", value: selected.configName },
                { label: "描述", value: selected.description },
                { label: "更新时间", value: selected.updatedAt },
              ]}
            />
            <div style={{ marginTop: 20 }}>
              <div className="detail-label" style={{ marginBottom: 8 }}>JSON 内容</div>
              <pre className="code-block">{selected.value}</pre>
            </div>
            <div className="button-row" style={{ marginTop: 20 }}>
              <Button variant="secondary" onClick={() => openEditModal(selected)}>
                修改配置
              </Button>
              <Button variant="danger" onClick={() => setPendingDelete(selected)}>
                删除配置
              </Button>
            </div>
          </>
        ) : null}
      </Drawer>

      <Modal
        description="演示用表单，结构与后续真实接口表单保持一致。"
        onClose={() => {
          setOpen(false);
          setFormError(null);
        }}
        open={open}
        title="新增配置"
      >
        <div className="panel-stack">
          <Field label="配置名">
            <Input placeholder="例如：project-config-demo" value={configName} onChange={(event) => setConfigName(event.target.value)} />
          </Field>
          <Field label="配置类型">
            <Input
              placeholder="例如：prompt_template / keyword_set / prompt_assembly"
              value={configType}
              onChange={(event) => setConfigType(event.target.value)}
            />
          </Field>
          <Field label="描述">
            <Input placeholder="简短说明用途" value={description} onChange={(event) => setDescription(event.target.value)} />
          </Field>
          <Field label="JSON 内容">
            <TextArea className="json-text-area" value={value} onChange={(event) => setValue(event.target.value)} />
          </Field>
          {formError ? <div className="muted-text" style={{ color: "#b42318" }}>{formError}</div> : null}
          <div className="button-row">
            <Button variant="secondary" onClick={formatCreateJson}>
              格式化 JSON
            </Button>
            <Button variant="primary" onClick={() => void handleCreateConfig()}>
              {submitting ? "保存中..." : "保存配置"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setOpen(false);
                setFormError(null);
              }}
            >
              取消
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        description="粘贴单条配置对象或配置数组，字段使用 config_name、config_type、config_value 和 description。"
        onClose={() => {
          setImportOpen(false);
          setImportError(null);
        }}
        open={importOpen}
        title="导入 JSON"
      >
        <div className="panel-stack">
          <Field label="导入内容">
            <TextArea
              className="json-text-area"
              placeholder={'{\n  "config_name": "complik_model_config",\n  "config_type": "model_runtime",\n  "config_value": {\n    "model": "gpt-5"\n  },\n  "description": "CompliK模型配置"\n}'}
              value={importValue}
              onChange={(event) => setImportValue(event.target.value)}
            />
          </Field>
          {importError ? <div className="muted-text" style={{ color: "#b42318" }}>{importError}</div> : null}
          <div className="button-row">
            <Button variant="secondary" onClick={formatImportJson}>
              格式化 JSON
            </Button>
            <Button variant="primary" onClick={() => void handleImportConfigs()}>
              {importSubmitting ? "导入中..." : "导入配置"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setImportOpen(false);
                setImportError(null);
              }}
            >
              取消
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        description="修改配置会覆盖当前配置值，请先确认 JSON 内容。"
        onClose={() => {
          setEditOpen(false);
          setEditError(null);
        }}
        open={editOpen}
        title="修改配置"
      >
        <div className="panel-stack">
          <Field label="配置名">
            <Input
              placeholder="例如：project-config-demo"
              value={editConfigName}
              onChange={(event) => setEditConfigName(event.target.value)}
            />
          </Field>
          <Field label="配置类型">
            <Input
              placeholder="例如：prompt_template / keyword_set / prompt_assembly"
              value={editConfigType}
              onChange={(event) => setEditConfigType(event.target.value)}
            />
          </Field>
          <Field label="描述">
            <Input
              placeholder="简短说明用途"
              value={editDescription}
              onChange={(event) => setEditDescription(event.target.value)}
            />
          </Field>
          <Field label="JSON 内容">
            <TextArea className="json-text-area" value={editValue} onChange={(event) => setEditValue(event.target.value)} />
          </Field>
          {editError ? <div className="muted-text" style={{ color: "#b42318" }}>{editError}</div> : null}
          <div className="button-row">
            <Button variant="secondary" onClick={formatEditJson}>
              格式化 JSON
            </Button>
            <Button variant="primary" onClick={() => void handleUpdateConfig()}>
              {editSubmitting ? "保存中..." : "保存修改"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setEditOpen(false);
                setEditError(null);
              }}
            >
              取消
            </Button>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        description={pendingDelete ? `删除后将从当前前端列表中移除配置 ${pendingDelete.configName}。` : ""}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => {
          if (!pendingDelete) return;
          void deleteConfigRecord(pendingDelete.configName).then(() => {
            if (selected?.id === pendingDelete.id) {
              setSelected(null);
            }
            setPendingDelete(null);
          });
        }}
        open={Boolean(pendingDelete)}
        title="删除配置"
      />
    </div>
  );
}
