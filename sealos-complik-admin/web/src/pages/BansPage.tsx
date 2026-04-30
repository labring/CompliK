import { useEffect, useMemo, useState } from "react";
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
import { MarkdownRenderer } from "../components/MarkdownRenderer";
import { useAppData } from "../contexts/AppDataContext";
import { useManagedOperatorOptions } from "../hooks/useOperatorOptions";
import { buildBanScreenshotPreviewURL } from "../lib/api";
import { summarizeMarkdown } from "../lib/utils";
import type { BanRecord } from "../types";

export function BansPage() {
  const navigate = useNavigate();
  const { banRecords, configRecords, createBanRecord, deleteBanRecord, unbanRecords } = useAppData();
  const [selected, setSelected] = useState<BanRecord | null>(null);
  const [open, setOpen] = useState(false);
  const [keyword, setKeyword] = useState("");
  const [operatorFilter, setOperatorFilter] = useState("");
  const [pendingDelete, setPendingDelete] = useState<BanRecord | null>(null);
  const [namespace, setNamespace] = useState("");
  const [reason, setReason] = useState("");
  const [banStartTime, setBanStartTime] = useState("");
  const [operatorName, setOperatorName] = useState("");
  const [screenshots, setScreenshots] = useState<File[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [previewingScreenshot, setPreviewingScreenshot] = useState<{ name: string; url: string } | null>(null);

  const { operatorConfigType, operatorOptions, operatorSource } = useManagedOperatorOptions(configRecords, [
    ...banRecords.map((item) => item.operatorName),
    ...unbanRecords.map((item) => item.operatorName),
  ]);

  const resetForm = () => {
    setNamespace("");
    setReason("");
    setBanStartTime("");
    setOperatorName("");
    setScreenshots([]);
  };

  const screenshotPreviews = useMemo(
    () =>
      screenshots.map((file) => ({
        file,
        url: URL.createObjectURL(file),
      })),
    [screenshots],
  );

  useEffect(() => {
    return () => {
      screenshotPreviews.forEach((item) => URL.revokeObjectURL(item.url));
    };
  }, [screenshotPreviews]);

  const appendScreenshots = (files: File[]) => {
    if (files.length === 0) {
      return;
    }

    setScreenshots((current) => [...current, ...files].slice(0, 6));
  };

  const removeScreenshot = (target: File) => {
    setScreenshots((current) =>
      current.filter(
        (file) =>
          !(
            file.name === target.name &&
            file.size === target.size &&
            file.lastModified === target.lastModified &&
            file.type === target.type
          ),
      ),
    );
  };

  const handleReasonPaste = (event: React.ClipboardEvent<HTMLTextAreaElement>) => {
    const imageFiles = Array.from(event.clipboardData.items)
      .filter((item) => item.kind === "file" && item.type.startsWith("image/"))
      .map((item) => item.getAsFile())
      .filter((file): file is File => file !== null);

    if (imageFiles.length === 0) {
      return;
    }

    event.preventDefault();
    appendScreenshots(imageFiles);
    setFormError(null);
  };

  const rows = useMemo(() => {
    return banRecords.filter((item) => {
      if (keyword && !item.namespace.toLowerCase().includes(keyword.toLowerCase())) {
        return false;
      }
      if (operatorFilter && item.operatorName !== operatorFilter) {
        return false;
      }
      return true;
    });
  }, [banRecords, keyword, operatorFilter]);

  const handleCreateBan = async () => {
    if (submitting) {
      return;
    }
    if (!namespace.trim() || !reason.trim() || !banStartTime.trim() || !operatorName.trim()) {
      setFormError("namespace、描述、开始时间、操作人均为必填。");
      return;
    }
    if (screenshots.length > 6) {
      setFormError("截图最多上传 6 张。");
      return;
    }

    setSubmitting(true);
    setFormError(null);
    try {
      await createBanRecord({
        namespace: namespace.trim(),
        reason: reason.trim(),
        banStartTime,
        operatorName: operatorName.trim(),
        screenshots,
      });
      setOpen(false);
      resetForm();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "新增封禁记录失败");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="page-container">
      <PageHeader
        kicker="Bans"
        title="封禁记录"
        description="录入和查看封禁记录，操作人从固定名单选择，描述使用纯文本输入，截图支持上传和粘贴。"
        actions={<Button variant="primary" onClick={() => setOpen(true)}>新增封禁</Button>}
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
        </div>
      </SurfaceCard>

      <SurfaceCard className="data-table-wrap" padded={false}>
        {rows.length > 0 ? (
          <table className="data-table">
            <thead>
              <tr>
                <th>namespace</th>
                <th>描述</th>
                <th>开始时间</th>
                <th>操作人</th>
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
                      {summarizeMarkdown(item.reason, 72) || (item.screenshotUrls.length > 0 ? `截图 ${item.screenshotUrls.length} 张` : "-")}
                    </button>
                  </td>
                  <td>{item.banStartTime}</td>
                  <td>{item.operatorName}</td>
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
              title="当前没有封禁记录"
              description="可以直接新增一条封禁记录。"
              action={<Button variant="primary" onClick={() => setOpen(true)}>新增封禁</Button>}
            />
          </div>
        )}
      </SurfaceCard>

      <Drawer
        description="这里展示描述内容和截图附件。"
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected ? selected.namespace : ""}
      >
        {selected ? (
          <>
            <DetailList
              items={[
                { label: "namespace", value: selected.namespace },
                { label: "开始时间", value: selected.banStartTime },
                { label: "操作人", value: selected.operatorName },
              ]}
            />
            <div className="ban-detail-section">
              <div className="detail-label">描述</div>
              <div className="detail-value">
                <MarkdownRenderer
                  content={selected.reason}
                  onImageClick={({ url, alt }) => setPreviewingScreenshot({ name: alt || "图片预览", url })}
                />
              </div>
            </div>
            <div className="ban-detail-section">
              <div className="detail-label">截图</div>
              {selected.screenshotUrls.length > 0 ? (
                <div className="screenshot-grid">
                  {selected.screenshotUrls.map((url, index) => {
                    const previewURL = buildBanScreenshotPreviewURL(url);
                    return (
                      <button
                        className="screenshot-card"
                        key={`${url}-${index}`}
                        type="button"
                        onClick={() => setPreviewingScreenshot({ name: `封禁截图 ${index + 1}`, url: previewURL })}
                      >
                        <img alt={`封禁截图 ${index + 1}`} className="screenshot-image" loading="lazy" src={previewURL} />
                        <span className="screenshot-caption">截图 {index + 1}</span>
                      </button>
                    );
                  })}
                </div>
              ) : (
                <div className="muted-text">当前没有截图附件</div>
              )}
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

      <Modal
        description="描述使用纯文本录入，支持在输入框里直接粘贴图片，截图会和封禁记录一起保存。"
        onClose={() => {
          setOpen(false);
          setFormError(null);
          resetForm();
        }}
        open={open}
        title="新增封禁"
      >
        <div className="panel-stack">
          <Field label="namespace">
            <Input placeholder="例如：prod-finance" value={namespace} onChange={(event) => setNamespace(event.target.value)} />
          </Field>
          <Field label="描述（TXT）">
            <div className="plain-text-input-shell">
              <textarea
                className="text-area plain-text-input-textarea"
                placeholder={"例如：\n封禁说明：违规链接已核实\n影响范围：prod-finance\n\n附上排查结论和后续动作。"}
                spellCheck={false}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                onPaste={handleReasonPaste}
              />
              {screenshotPreviews.length > 0 ? (
                <div className="plain-text-input-attachments">
                  {screenshotPreviews.map(({ file, url }) => (
                    <div className="plain-text-attachment-card" key={`${file.name}-${file.size}-${file.lastModified}`}>
                      <img
                        alt={file.name}
                        className="plain-text-attachment-image"
                        src={url}
                        onClick={() => setPreviewingScreenshot({ name: file.name, url })}
                      />
                      <div className="plain-text-attachment-meta">
                        <span className="plain-text-attachment-name">{file.name}</span>
                        <button className="table-row-button" type="button" onClick={() => removeScreenshot(file)}>
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
            <div className="muted-text">支持直接输入纯文本，也支持在输入框里复制粘贴图片。</div>
          </Field>
          <Field label="开始时间">
            <Input type="datetime-local" value={banStartTime} onChange={(event) => setBanStartTime(event.target.value)} />
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
          <Field label="截图附件">
            <div className="upload-stack">
              <Input
                accept="image/png,image/jpeg,image/webp,image/gif"
                multiple
                type="file"
                onChange={(event) => {
                  appendScreenshots(Array.from(event.target.files ?? []));
                  event.target.value = "";
                }}
              />
              <div className="muted-text">支持 PNG、JPG、WEBP、GIF，最多 6 张。文件选择和粘贴图片会合并到同一列表。</div>
              {screenshots.length > 0 ? (
                <div className="upload-list">
                  {screenshots.map((file) => (
                    <div className="upload-item" key={`${file.name}-${file.size}-${file.lastModified}`}>
                      <span>{file.name}</span>
                      <div className="upload-item-actions">
                        <span className="muted-text">{Math.max(1, Math.round(file.size / 1024))} KB</span>
                        <button className="table-row-button" type="button" onClick={() => removeScreenshot(file)}>
                          删除
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          </Field>
          {formError ? <div className="muted-text" style={{ color: "#b42318" }}>{formError}</div> : null}
          <div className="button-row">
            <Button variant="primary" onClick={() => void handleCreateBan()}>
              {submitting ? "保存中..." : "保存封禁记录"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setOpen(false);
                setFormError(null);
                resetForm();
              }}
            >
              取消
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        description="单击图片可查看大图。"
        onClose={() => setPreviewingScreenshot(null)}
        open={Boolean(previewingScreenshot)}
        title={previewingScreenshot?.name ?? "图片预览"}
      >
        {previewingScreenshot ? (
          <div className="image-preview-modal-body">
            <img alt={previewingScreenshot.name} className="image-preview-modal-image" src={previewingScreenshot.url} />
          </div>
        ) : null}
      </Modal>

      <ConfirmModal
        description={pendingDelete ? `删除后将从当前前端列表中移除 namespace ${pendingDelete.namespace} 的封禁记录。` : ""}
        onClose={() => setPendingDelete(null)}
        onConfirm={() => {
          if (!pendingDelete) return;
          void deleteBanRecord(pendingDelete.apiId).then(() => {
            if (selected?.id === pendingDelete.id) {
              setSelected(null);
            }
            setPendingDelete(null);
          });
        }}
        open={Boolean(pendingDelete)}
        title="删除封禁记录"
      />
    </div>
  );
}
