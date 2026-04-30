import { RefreshCw } from "lucide-react";
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
  PageHeader,
  Select,
  SurfaceCard,
} from "../components/ui";
import { MarkdownRenderer } from "../components/MarkdownRenderer";
import { useAppData } from "../contexts/AppDataContext";
import { formatViolationTypeLabel } from "../lib/utils";
import type { ViolationRecord, ViolationType } from "../types";

export function ViolationsPage() {
  const navigate = useNavigate();
  const { deleteViolationRecord, error, isLoading, refreshAll, violations } = useAppData();
  const [tab, setTab] = useState<ViolationType>("complik");
  const [selected, setSelected] = useState<ViolationRecord | null>(null);
  const [namespaceKeyword, setNamespaceKeyword] = useState("");
  const [pendingDelete, setPendingDelete] = useState<ViolationRecord | null>(null);

  const rows = useMemo(() => {
    return violations.filter((item) => {
      if (item.type !== tab) return false;
      if (namespaceKeyword && !item.namespace.toLowerCase().includes(namespaceKeyword.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [namespaceKeyword, tab, violations]);

  return (
    <div className="page-container">
      <PageHeader
        kicker="Risk Center"
        title="违规中心"
        description="在同一套布局里查看内容违规和进程违规两类记录。"
        actions={
          <Button
            variant="secondary"
            onClick={() => {
              void refreshAll();
            }}
          >
            <RefreshCw size={16} /> 刷新
          </Button>
        }
      />

      <SurfaceCard>
        <div className="toolbar">
          <Field label="namespace">
            <Input placeholder="按 namespace 搜索" value={namespaceKeyword} onChange={(event) => setNamespaceKeyword(event.target.value)} />
          </Field>
          <Field label="时间范围">
            <Select defaultValue="7d">
              <option value="24h">最近 24 小时</option>
              <option value="7d">最近 7 天</option>
              <option value="30d">最近 30 天</option>
            </Select>
          </Field>
          <Field label="关键字">
            <Input placeholder="detector / process / message" />
          </Field>
        </div>
      </SurfaceCard>

      <div className="tab-row" role="tablist" aria-label="违规类型">
        <button className={`tab-button ${tab === "complik" ? "active" : ""}`} onClick={() => setTab("complik")} type="button">
          内容违规
        </button>
        <button className={`tab-button ${tab === "procscan" ? "active" : ""}`} onClick={() => setTab("procscan")} type="button">
          进程违规
        </button>
      </div>

      <SurfaceCard className="data-table-wrap" padded={false}>
        {error ? (
          <div style={{ padding: 20 }}>
            <EmptyState
              title="违规数据加载失败"
              description={error}
              action={
                <Button
                  variant="secondary"
                  onClick={() => {
                    void refreshAll();
                  }}
                >
                  重新加载
                </Button>
              }
            />
          </div>
        ) : isLoading ? (
          <div style={{ padding: 20 }}>
            <EmptyState
              title="违规数据加载中"
              description="正在从后端同步内容违规和进程违规记录。"
            />
          </div>
        ) : rows.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>namespace</th>
                <th>{tab === "complik" ? "detector" : "进程 / Pod"}</th>
                <th>{tab === "complik" ? "URL" : "节点 / 说明"}</th>
                <th>发现时间</th>
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
                      <strong>{tab === "complik" ? (item.detectorName ?? "-") : (item.processName ?? "-")}</strong>
                      {tab === "complik" ? null : <div className="muted-text">{item.podName ?? "-"}</div>}
                    </button>
                  </td>
                  <td>
                    {tab === "complik" ? (
                      <div>{item.url ?? "-"}</div>
                    ) : (
                      <>
                        <div>{item.nodeName ?? "-"}</div>
                        <div className="muted-text">{item.message ?? "-"}</div>
                      </>
                    )}
                  </td>
                  <td>{item.detectedAt}</td>
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
              title="当前筛选条件下没有违规记录"
              description="可以切换页签、清空筛选，或等待后端同步更多数据。"
            />
          </div>
        )}
      </SurfaceCard>

      <Drawer
        description="点开记录后停留在当前页，右侧抽屉展示完整字段。"
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected ? `${selected.namespace} - 违规详情` : ""}
      >
        {selected ? (
          <>
            <DetailList
              items={[
                { label: "类型", value: formatViolationTypeLabel(selected.type) },
                { label: "namespace", value: selected.namespace },
                { label: "detector / process", value: selected.detectorName ?? selected.processName ?? "-" },
                { label: "资源 / pod", value: selected.resourceName ?? selected.podName ?? "-" },
                { label: "host / node", value: selected.host ?? selected.nodeName ?? "-" },
                { label: "URL / message", value: selected.url ?? selected.message ?? "-" },
                { label: "关键词", value: selected.keywords?.join(", ") ?? "-" },
                { label: "发现时间", value: selected.detectedAt },
                { label: "原始负载", value: selected.rawPayload ?? "-" },
              ]}
            />
            <div className="ban-detail-section">
              <div className="detail-label">描述</div>
              <div className="detail-value">
                <MarkdownRenderer content={selected.description} />
              </div>
            </div>
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

      <ConfirmModal
        description={pendingDelete ? `删除后仅移除当前这条违规记录（namespace: ${pendingDelete.namespace}）。` : ""}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => {
          if (!pendingDelete) return;
          void deleteViolationRecord({
            id: pendingDelete.apiId,
            type: pendingDelete.type,
          }).then(() => {
            if (selected?.id === pendingDelete.id) {
              setSelected(null);
            }
            setPendingDelete(null);
          });
        }}
        open={Boolean(pendingDelete)}
        title="删除违规记录"
      />
    </div>
  );
}
