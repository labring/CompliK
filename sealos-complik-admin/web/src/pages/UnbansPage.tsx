import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
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
  Select,
  SurfaceCard,
} from "../components/ui";
import { useAppData } from "../contexts/AppDataContext";
import { useManagedOperatorOptions } from "../hooks/useOperatorOptions";
import type { UnbanRecord } from "../types";

export function UnbansPage() {
  const navigate = useNavigate();
  const { banRecords, configRecords, createUnbanRecord, unbanRecords, deleteUnbanRecord } = useAppData();
  const [selected, setSelected] = useState<UnbanRecord | null>(null);
  const [open, setOpen] = useState(false);
  const [keyword, setKeyword] = useState("");
  const [operatorFilter, setOperatorFilter] = useState("");
  const [pendingDelete, setPendingDelete] = useState<UnbanRecord | null>(null);
  const [namespace, setNamespace] = useState("");
  const [operatorName, setOperatorName] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const { operatorConfigType, operatorOptions, operatorSource } = useManagedOperatorOptions(configRecords, [
    ...banRecords.map((item) => item.operatorName),
    ...unbanRecords.map((item) => item.operatorName),
  ]);

  const rows = useMemo(() => {
    return unbanRecords.filter((item) => {
      if (!item.namespace.toLowerCase().includes(keyword.toLowerCase())) {
        return false;
      }
      if (operatorFilter && item.operatorName !== operatorFilter) {
        return false;
      }
      return true;
    });
  }, [keyword, operatorFilter, unbanRecords]);

  const handleCreateUnban = async () => {
    if (!namespace.trim() || !operatorName.trim()) {
      setFormError("namespace 和操作人均为必填。");
      return;
    }

    setSubmitting(true);
    setFormError(null);
    try {
      await createUnbanRecord({
        namespace: namespace.trim(),
        operatorName: operatorName.trim(),
      });
      setOpen(false);
      setNamespace("");
      setOperatorName("");
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "新增解封记录失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="page-container">
      <PageHeader
        kicker="Unbans"
        title="解封记录"
        description="页面复杂度低于封禁记录，只保留必要筛选和最小录入字段。"
        actions={<Button variant="primary" onClick={() => setOpen(true)}>新增解封</Button>}
      />

      <SurfaceCard>
        <div className="toolbar">
          <Field label="namespace">
            <Input placeholder="按 namespace 搜索" value={keyword} onChange={(event) => setKeyword(event.target.value)} />
          </Field>
          <Field label="操作人">
            <Select value={operatorFilter} onChange={(event) => setOperatorFilter(event.target.value)}>
              <option value="">全部操作人</option>
              {operatorOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="时间范围">
            <Select defaultValue="7d">
              <option value="24h">最近 24 小时</option>
              <option value="7d">最近 7 天</option>
              <option value="30d">最近 30 天</option>
            </Select>
          </Field>
        </div>
      </SurfaceCard>

      <SurfaceCard className="data-table-wrap" padded={false}>
        {rows.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>namespace</th>
                <th>操作人</th>
                <th>时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id}>
                  <td>
                    <button className="namespace-link table-row-button" onClick={() => navigate(`/namespaces/${item.namespace}`)} type="button">
                      {item.namespace}
                    </button>
                  </td>
                  <td>
                    <button className="table-row-button" onClick={() => setSelected(item)} type="button">
                      {item.operatorName}
                    </button>
                  </td>
                  <td>{item.createdAt}</td>
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
              title="当前没有解封记录"
              description="可以直接新增一条解封记录。"
              action={<Button variant="primary" onClick={() => setOpen(true)}>新增解封</Button>}
            />
          </div>
        )}
      </SurfaceCard>

      <Drawer
        description="解封记录详情保持轻量，只展示当前接口已有字段。"
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected ? selected.namespace : ""}
      >
        {selected ? (
          <>
            <DetailList
              items={[
                { label: "namespace", value: selected.namespace },
                { label: "操作人", value: selected.operatorName },
                { label: "创建时间", value: selected.createdAt },
              ]}
            />
            <div className="button-row" style={{ marginTop: 20 }}>
              <Button variant="secondary" onClick={() => navigate(`/namespaces/${selected.namespace}`)}>
                查看 namespace 详情
              </Button>
              <Button variant="danger" onClick={() => setPendingDelete(selected)}>
                删除记录
              </Button>
            </div>
          </>
        ) : null}
      </Drawer>

      <Modal
        description="只保留 namespace 和操作人两个必填项。"
        onClose={() => {
          setOpen(false);
          setFormError(null);
        }}
        open={open}
        title="新增解封"
      >
        <div className="panel-stack">
          <Field label="namespace">
            <Input placeholder="例如：growth-ops" value={namespace} onChange={(event) => setNamespace(event.target.value)} />
          </Field>
          <Field label="操作人">
            <Select value={operatorName} onChange={(event) => setOperatorName(event.target.value)}>
              <option value="">请选择操作人</option>
              {operatorOptions.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </Select>
          </Field>
          <div className="muted-text">
            {operatorSource === "config"
              ? `操作人名单来自配置类型 ${operatorConfigType}。`
              : `当前操作人名单来自历史记录。建议创建 config_type 为 ${operatorConfigType} 的配置，JSON 内容使用 {"operators":["张三","李四"]}。`}
          </div>
          {formError ? <div className="muted-text" style={{ color: "#b42318" }}>{formError}</div> : null}
          <div className="button-row">
            <Button variant="primary" onClick={() => void handleCreateUnban()}>
              {submitting ? "保存中..." : "保存解封记录"}
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

      <ConfirmModal
        description={pendingDelete ? `删除后仅移除当前这条解封记录（namespace: ${pendingDelete.namespace}，操作人: ${pendingDelete.operatorName}）。` : ""}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => {
          if (!pendingDelete) return;
          void deleteUnbanRecord(pendingDelete.apiId).then(() => {
            if (selected?.id === pendingDelete.id) {
              setSelected(null);
            }
            setPendingDelete(null);
          });
        }}
        open={Boolean(pendingDelete)}
        title="删除解封记录"
      />
    </div>
  );
}
