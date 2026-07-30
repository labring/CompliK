import { RefreshCw, RotateCcw, Save } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AUTOBAN_POLICY_CONFIG_NAME,
  AUTOBAN_POLICY_CONFIG_TYPE,
  listConfigRecordsByType,
  saveAutobanPolicy,
} from "../lib/api";
import { Button, Field, Input, PageHeader, StatusPill, SurfaceCard, TextArea } from "../components/ui";
import { useAppData } from "../contexts/AppDataContext";
import type { AutobanPolicy, ConfigRecord, RiskTone } from "../types";

type AutobanPolicyForm = {
  enabled: boolean;
  dryRun: boolean;
  operatorName: string;
  reasonPrefix: string;
  complikEnabled: boolean;
  procscanEnabled: boolean;
  processNameAllowlist: string;
  processNameDenylist: string;
  namespaceAllowlist: string;
  namespaceDenylist: string;
};

const systemNamespaceDenylist = ["kube-system", "sealos", "block-system"];

const defaultPolicy: AutobanPolicy = {
  enabled: false,
  dryRun: true,
  operatorName: "system/autoban",
  reasonPrefix: "Admin auto-ban",
  sources: {
    complik: { enabled: false },
    procscan: { enabled: true },
  },
  processNameAllowlist: [],
  processNameDenylist: [],
  namespaceAllowlist: [],
  namespaceDenylist: systemNamespaceDenylist,
};

function readObject(value: unknown): Record<string, unknown> | undefined {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function readBoolean(value: unknown, fallback: boolean) {
  return typeof value === "boolean" ? value : fallback;
}

function readString(value: unknown, fallback: string) {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : fallback;
}

function readStringList(value: unknown) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean);
}

function readSourceEnabled(value: unknown, fallback: boolean) {
  if (typeof value === "boolean") {
    return value;
  }

  const source = readObject(value);
  return readBoolean(source?.enabled, fallback);
}

function parsePolicyValue(value: string): AutobanPolicy {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return defaultPolicy;
  }

  const raw = readObject(parsed);
  if (!raw) {
    return defaultPolicy;
  }

  const sources = readObject(raw.sources);

  return {
    enabled: readBoolean(raw.enabled, defaultPolicy.enabled),
    dryRun: readBoolean(raw.dryRun ?? raw.dry_run, defaultPolicy.dryRun),
    operatorName: readString(raw.operatorName ?? raw.operator_name, defaultPolicy.operatorName),
    reasonPrefix: readString(raw.reasonPrefix ?? raw.reason_prefix, defaultPolicy.reasonPrefix),
    sources: {
      complik: {
        enabled: readSourceEnabled(sources?.complik, defaultPolicy.sources.complik.enabled),
      },
      procscan: {
        enabled: readSourceEnabled(sources?.procscan, defaultPolicy.sources.procscan.enabled),
      },
    },
    processNameAllowlist: readStringList(raw.processNameAllowlist ?? raw.process_name_allowlist),
    processNameDenylist: readStringList(raw.processNameDenylist ?? raw.process_name_denylist),
    namespaceAllowlist: readStringList(raw.namespaceAllowlist ?? raw.namespace_allowlist),
    namespaceDenylist: readStringList(raw.namespaceDenylist ?? raw.namespace_denylist),
  };
}

function formatList(values: string[]) {
  return values.join("\n");
}

function parseList(value: string) {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function toForm(policy: AutobanPolicy): AutobanPolicyForm {
  return {
    enabled: policy.enabled,
    dryRun: policy.dryRun,
    operatorName: policy.operatorName,
    reasonPrefix: policy.reasonPrefix,
    complikEnabled: policy.sources.complik.enabled,
    procscanEnabled: policy.sources.procscan.enabled,
    processNameAllowlist: formatList(policy.processNameAllowlist),
    processNameDenylist: formatList(policy.processNameDenylist),
    namespaceAllowlist: formatList(policy.namespaceAllowlist),
    namespaceDenylist: formatList(policy.namespaceDenylist),
  };
}

function toPolicy(form: AutobanPolicyForm): AutobanPolicy {
  return {
    enabled: form.enabled,
    dryRun: form.dryRun,
    operatorName: form.operatorName.trim() || defaultPolicy.operatorName,
    reasonPrefix: form.reasonPrefix.trim() || defaultPolicy.reasonPrefix,
    sources: {
      complik: {
        enabled: form.complikEnabled,
      },
      procscan: {
        enabled: form.procscanEnabled,
      },
    },
    processNameAllowlist: parseList(form.processNameAllowlist),
    processNameDenylist: parseList(form.processNameDenylist),
    namespaceAllowlist: parseList(form.namespaceAllowlist),
    namespaceDenylist: parseList(form.namespaceDenylist),
  };
}

function pickPolicyConfig(configs: ConfigRecord[]) {
  return (
    configs.find((item) => item.configName.trim().toLowerCase() === AUTOBAN_POLICY_CONFIG_NAME) ??
    configs.find((item) => item.configType === AUTOBAN_POLICY_CONFIG_TYPE)
  );
}

function getStatusTone(form: AutobanPolicyForm): RiskTone {
  if (!form.enabled) {
    return "neutral";
  }

  if (form.dryRun) {
    return "warn";
  }

  return "danger";
}

function getStatusLabel(form: AutobanPolicyForm) {
  if (!form.enabled) {
    return "关闭";
  }

  if (form.dryRun) {
    return "Dry-run";
  }

  return "生效中";
}

function getSourceLabel(form: AutobanPolicyForm) {
  const enabledSources = [
    form.complikEnabled ? "CompliK" : "",
    form.procscanEnabled ? "ProcScan" : "",
  ].filter(Boolean);

  return enabledSources.length > 0 ? enabledSources.join(" / ") : "未启用";
}

function getRuleSummary(allowlist: string, denylist: string, emptyLabel: string) {
  const allowCount = parseList(allowlist).length;
  const denyCount = parseList(denylist).length;

  if (allowCount > 0 && denyCount > 0) {
    return `${allowCount} 条允许 / ${denyCount} 条排除`;
  }

  if (allowCount > 0) {
    return `${allowCount} 条允许名单`;
  }

  if (denyCount > 0) {
    return `${denyCount} 条排除名单`;
  }

  return emptyLabel;
}

function CheckboxRow({
  checked,
  label,
  description,
  onChange,
}: {
  checked: boolean;
  label: string;
  description: string;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="check-row">
      <input checked={checked} onChange={(event) => onChange(event.target.checked)} type="checkbox" />
      <span>
        <strong>{label}</strong>
        <span>{description}</span>
      </span>
    </label>
  );
}

function SummaryItem({
  label,
  value,
  tone,
  description,
}: {
  label: string;
  value: string;
  tone: RiskTone;
  description: string;
}) {
  return (
    <div className="policy-summary-item">
      <span className="detail-label">{label}</span>
      <div className="policy-summary-value">
        <StatusPill tone={tone}>{value}</StatusPill>
      </div>
      <p className="muted-text">{description}</p>
    </div>
  );
}

export function AutobanPolicyPage() {
  const { configRecords, refreshAll } = useAppData();
  const [form, setForm] = useState<AutobanPolicyForm>(() => toForm(defaultPolicy));
  const [policyConfig, setPolicyConfig] = useState<ConfigRecord | null>(null);
  const [loadedFallbackConfig, setLoadedFallbackConfig] = useState<ConfigRecord | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  const previewPolicy = useMemo(() => toPolicy(form), [form]);
  const previewJSON = useMemo(() => JSON.stringify(previewPolicy, null, 2), [previewPolicy]);

  const loadPolicy = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    setSavedMessage(null);

    try {
      const typedConfigs = await listConfigRecordsByType(AUTOBAN_POLICY_CONFIG_TYPE);
      const canonicalConfig =
        typedConfigs.find((item) => item.configName.trim().toLowerCase() === AUTOBAN_POLICY_CONFIG_NAME) ?? null;
      const nextConfig = canonicalConfig ?? typedConfigs[0] ?? pickPolicyConfig(configRecords) ?? null;
      const nextPolicy = nextConfig ? parsePolicyValue(nextConfig.value) : defaultPolicy;

      setPolicyConfig(canonicalConfig);
      setLoadedFallbackConfig(canonicalConfig ? null : nextConfig);
      setForm(toForm(nextPolicy));
    } catch (err) {
      setError(err instanceof Error ? err.message : "自动封禁策略加载失败");
    } finally {
      setIsLoading(false);
    }
  }, [configRecords]);

  useEffect(() => {
    void loadPolicy();
  }, [loadPolicy]);

  const updateForm = <TKey extends keyof AutobanPolicyForm>(key: TKey, value: AutobanPolicyForm[TKey]) => {
    setForm((current) => ({ ...current, [key]: value }));
    setSavedMessage(null);
  };

  const handleSave = async () => {
    setIsSaving(true);
    setError(null);
    setSavedMessage(null);

    try {
      await saveAutobanPolicy(previewPolicy, policyConfig?.configName);
      await refreshAll();
      await loadPolicy();
      setSavedMessage("自动封禁策略已保存。");
    } catch (err) {
      setError(err instanceof Error ? err.message : "自动封禁策略保存失败");
    } finally {
      setIsSaving(false);
    }
  };

  const resetToDefault = () => {
    setForm(toForm(defaultPolicy));
    setSavedMessage(null);
    setError(null);
  };

  return (
    <div className="page-container">
      <PageHeader
        kicker="Autoban"
        title="自动封禁"
        description="配置 admin 在收到违规事件后自动创建封禁记录，并由 block-controller 执行 namespace 锁定。"
        actions={
          <>
            <Button disabled={isLoading || isSaving} variant="secondary" onClick={() => void loadPolicy()}>
              <RefreshCw size={16} />
              重新加载
            </Button>
            <Button disabled={isSaving} variant="primary" onClick={() => void handleSave()}>
              <Save size={16} />
              {isSaving ? "保存中..." : "保存策略"}
            </Button>
          </>
        }
      />

      {error ? <div className="policy-message policy-message-error">{error}</div> : null}
      {savedMessage ? <div className="policy-message policy-message-success">{savedMessage}</div> : null}
      {loadedFallbackConfig ? (
        <div className="policy-message">
          当前读取的是同类型配置 {loadedFallbackConfig.configName}，保存后会写入规范配置 {AUTOBAN_POLICY_CONFIG_NAME}。
        </div>
      ) : null}

      <SurfaceCard>
        <div className="policy-summary-grid">
          <SummaryItem
            description={form.dryRun ? "仅记录将要封禁的对象，不写入封禁记录。" : "匹配策略后会创建封禁记录。"}
            label="运行状态"
            tone={getStatusTone(form)}
            value={getStatusLabel(form)}
          />
          <SummaryItem
            description="只有启用的来源会进入自动封禁判断。"
            label="触发来源"
            tone={form.complikEnabled || form.procscanEnabled ? "info" : "neutral"}
            value={getSourceLabel(form)}
          />
          <SummaryItem
            description="denylist 优先于 allowlist；allowlist 为空时默认允许。"
            label="命名空间"
            tone={parseList(form.namespaceAllowlist).length > 0 ? "warn" : "info"}
            value={getRuleSummary(form.namespaceAllowlist, form.namespaceDenylist, "全部允许")}
          />
          <SummaryItem
            description="进程名规则只作用于 ProcScan 上报的 process_name。"
            label="进程名"
            tone={parseList(form.processNameAllowlist).length > 0 ? "warn" : "info"}
            value={getRuleSummary(form.processNameAllowlist, form.processNameDenylist, "全部允许")}
          />
        </div>
      </SurfaceCard>

      <div className="split-grid policy-split-grid">
        <SurfaceCard>
          <div className="panel-stack">
            <section className="policy-section">
              <div className="section-title-row">
                <div>
                  <h2 className="section-title">策略开关</h2>
                  <p className="section-subtitle">控制自动封禁是否参与处理，以及是否只做 dry-run。</p>
                </div>
                <Button variant="secondary" onClick={resetToDefault}>
                  <RotateCcw size={16} />
                  载入默认值
                </Button>
              </div>
              <div className="checkbox-group">
                <CheckboxRow
                  checked={form.enabled}
                  description="关闭时 admin 仍会记录违规事件，但不会创建自动封禁。"
                  label="启用自动封禁"
                  onChange={(checked) => updateForm("enabled", checked)}
                />
                <CheckboxRow
                  checked={form.dryRun}
                  description="开启后只输出 dry-run 日志，不写入封禁记录。"
                  label="Dry-run 模式"
                  onChange={(checked) => updateForm("dryRun", checked)}
                />
              </div>
            </section>

            <section className="policy-section">
              <div>
                <h2 className="section-title">触发来源</h2>
                <p className="section-subtitle">CompliK 和 ProcScan 可以独立控制。</p>
              </div>
              <div className="checkbox-group two-column">
                <CheckboxRow
                  checked={form.complikEnabled}
                  description="浏览器合规检测等 CompliK 违规事件。"
                  label="CompliK"
                  onChange={(checked) => updateForm("complikEnabled", checked)}
                />
                <CheckboxRow
                  checked={form.procscanEnabled}
                  description="进程扫描违规事件，支持按 process_name 过滤。"
                  label="ProcScan"
                  onChange={(checked) => updateForm("procscanEnabled", checked)}
                />
              </div>
            </section>

            <section className="policy-section">
              <div>
                <h2 className="section-title">封禁记录</h2>
                <p className="section-subtitle">自动创建封禁记录时使用的操作人和原因前缀。</p>
              </div>
              <div className="policy-form-grid">
                <Field label="操作人">
                  <Input
                    placeholder="system/autoban"
                    value={form.operatorName}
                    onChange={(event) => updateForm("operatorName", event.target.value)}
                  />
                </Field>
                <Field label="原因前缀">
                  <Input
                    placeholder="Admin auto-ban"
                    value={form.reasonPrefix}
                    onChange={(event) => updateForm("reasonPrefix", event.target.value)}
                  />
                </Field>
              </div>
            </section>

            <section className="policy-section">
              <div>
                <h2 className="section-title">进程名规则</h2>
                <p className="section-subtitle">每行一个进程名，也可以用英文逗号分隔；denylist 优先。</p>
              </div>
              <div className="policy-form-grid">
                <Field label="Process allowlist">
                  <TextArea
                    className="compact-text-area"
                    placeholder={"xmrig\nminerd"}
                    value={form.processNameAllowlist}
                    onChange={(event) => updateForm("processNameAllowlist", event.target.value)}
                  />
                </Field>
                <Field label="Process denylist">
                  <TextArea
                    className="compact-text-area"
                    placeholder={"nginx\nsystemd"}
                    value={form.processNameDenylist}
                    onChange={(event) => updateForm("processNameDenylist", event.target.value)}
                  />
                </Field>
              </div>
            </section>

            <section className="policy-section">
              <div>
                <h2 className="section-title">命名空间规则</h2>
                <p className="section-subtitle">allowlist 非空时只处理名单内 namespace；denylist 始终优先。</p>
              </div>
              <div className="policy-form-grid">
                <Field label="Namespace allowlist">
                  <TextArea
                    className="compact-text-area"
                    placeholder="tenant-a"
                    value={form.namespaceAllowlist}
                    onChange={(event) => updateForm("namespaceAllowlist", event.target.value)}
                  />
                </Field>
                <Field label="Namespace denylist">
                  <TextArea
                    className="compact-text-area"
                    placeholder={systemNamespaceDenylist.join("\n")}
                    value={form.namespaceDenylist}
                    onChange={(event) => updateForm("namespaceDenylist", event.target.value)}
                  />
                </Field>
              </div>
            </section>
          </div>
        </SurfaceCard>

        <SurfaceCard>
          <div className="panel-stack">
            <div>
              <h2 className="section-title">JSON 预览</h2>
              <p className="section-subtitle">保存后写入 config_name 为 {AUTOBAN_POLICY_CONFIG_NAME} 的项目配置。</p>
            </div>
            <pre className="code-block policy-code-block">{previewJSON}</pre>
          </div>
        </SurfaceCard>
      </div>
    </div>
  );
}
