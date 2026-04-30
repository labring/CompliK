import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import {
  createBanRecord as apiCreateBanRecord,
  createCommitmentRecord as apiCreateCommitmentRecord,
  createConfigRecord as apiCreateConfigRecord,
  createUnbanRecord as apiCreateUnbanRecord,
  deleteBanRecord as apiDeleteBanRecord,
  deleteCommitmentRecord as apiDeleteCommitmentRecord,
  deleteConfigRecord as apiDeleteConfigRecord,
  deleteUnbanRecord as apiDeleteUnbanRecord,
  deleteViolationRecord as apiDeleteViolationRecord,
  listBanRecords,
  listCommitmentRecords,
  listConfigRecords,
  listUnbanRecords,
  listViolationRecords,
  updateConfigRecord as apiUpdateConfigRecord,
} from "../lib/api";
import { summarizeMarkdown, toTimestamp } from "../lib/utils";
import type {
  ActivityItem,
  AppDataContextValue,
  BanRecord,
  CommitmentRecord,
  ConfigRecord,
  CreateBanInput,
  CreateCommitmentInput,
  CreateConfigInput,
  CreateUnbanInput,
  NamespaceProfile,
  QuickLinkItem,
  StatCardItem,
  TimelineRecord,
  UnbanRecord,
  UpdateConfigInput,
  ViolationRecord,
} from "../types";

const quickLinks: QuickLinkItem[] = [
  {
    title: "进入违规中心",
    description: "查看两类违规记录，并在右侧抽屉核对详情。",
    targetPath: "/violations",
  },
  {
    title: "查看封禁记录",
    description: "核对当前有效封禁，并补录新的封禁信息。",
    targetPath: "/bans",
  },
  {
    title: "维护项目配置",
    description: "查看配置类型、描述和 JSON 内容。",
    targetPath: "/configs",
  },
];

const defaultValue: AppDataContextValue = {
  isLoading: true,
  error: null,
  stats: [],
  latestViolations: [],
  latestActions: [],
  quickLinks,
  namespaceProfiles: [],
  configRecords: [],
  commitmentRecords: [],
  banRecords: [],
  unbanRecords: [],
  violations: [],
  refreshAll: async () => undefined,
  createConfigRecord: async () => undefined,
  updateConfigRecord: async () => undefined,
  createCommitmentRecord: async () => undefined,
  createBanRecord: async () => undefined,
  createUnbanRecord: async () => undefined,
  deleteConfigRecord: async () => undefined,
  deleteCommitmentRecord: async () => undefined,
  deleteBanRecord: async (_id: number) => undefined,
  deleteUnbanRecord: async (_id: number) => undefined,
  deleteViolationRecord: async () => undefined,
};

const AppDataContext = createContext<AppDataContextValue>(defaultValue);

function getViolationTone(type: ViolationRecord["type"]): ActivityItem["tone"] {
  return type === "complik" ? "danger" : "warn";
}

function describeBanRecord(item: BanRecord) {
  const details = [`操作人 ${item.operatorName}`];
  const reasonSummary = summarizeMarkdown(item.reason, 48);
  if (reasonSummary) {
    details.push(`描述 ${reasonSummary}`);
  }
  if (item.screenshotUrls.length > 0) {
    details.push(`截图 ${item.screenshotUrls.length} 张`);
  }

  return details.join("，");
}

function buildStats(violations: ViolationRecord[], bans: BanRecord[], unbans: UnbanRecord[]): StatCardItem[] {
  const violationNamespaces = new Set(violations.map((item) => item.namespace));
  const now = Date.now();
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayStartTime = todayStart.getTime();

  const todayViolationCount = violations.filter((item) => toTimestamp(item.detectedAt) >= todayStartTime).length;
  const todayActionCount =
    bans.filter((item) => toTimestamp(item.createdAt) >= todayStartTime).length +
    unbans.filter((item) => toTimestamp(item.createdAt) >= todayStartTime).length;
  const activeBanCount = bans.filter((item) => item.active && toTimestamp(item.banStartTime) <= now).length;

  return [
    {
      label: "违规 namespace 数",
      value: String(violationNamespaces.size),
      delta: `${violations.length} 条违规记录`,
      tone: "danger",
      description: "按当前违规记录对应的 namespace 去重统计。",
      targetPath: "/violations",
    },
    {
      label: "当前封禁数",
      value: String(activeBanCount),
      delta: `${bans.length} 条封禁记录`,
      tone: "warn",
      description: "按当前仍处于有效期内的封禁记录统计。",
      targetPath: "/bans",
    },
    {
      label: "今日新增违规",
      value: String(todayViolationCount),
      delta: `${violations.length} 条累计记录`,
      tone: "info",
      description: "包含内容违规和进程违规两类事件。",
      targetPath: "/violations",
    },
    {
      label: "今日新增处置",
      value: String(todayActionCount),
      delta: `${unbans.length} 条解封记录`,
      tone: "success",
      description: "包含今日新增封禁和解封动作。",
      targetPath: "/unbans",
    },
  ];
}

function buildLatestViolations(violations: ViolationRecord[]): ActivityItem[] {
  return [...violations]
    .sort((a, b) => toTimestamp(b.detectedAt) - toTimestamp(a.detectedAt))
    .slice(0, 3)
    .map((item) => ({
      id: item.id,
      namespace: item.namespace,
      summary:
        item.type === "complik"
          ? `${item.detectorName ?? "内容检测器"} 发现内容违规记录`
          : `${item.processName ?? "进程检测器"} 命中进程规则`,
      time: item.detectedAt,
      tone: getViolationTone(item.type),
      targetPath: `/namespaces/${item.namespace}`,
    }));
}

function buildLatestActions(
  bans: BanRecord[],
  unbans: UnbanRecord[],
  commitments: CommitmentRecord[],
): ActivityItem[] {
  const actions: Array<ActivityItem & { sortTime: number }> = [
    ...bans.map((item) => ({
      id: item.id,
      namespace: item.namespace,
      summary: `新增封禁记录，${describeBanRecord(item)}`,
      time: item.createdAt,
      tone: "warn" as const,
      targetPath: "/bans",
      sortTime: toTimestamp(item.createdAt),
    })),
    ...unbans.map((item) => ({
      id: item.id,
      namespace: item.namespace,
      summary: `新增解封记录，操作人 ${item.operatorName}`,
      time: item.createdAt,
      tone: "success" as const,
      targetPath: "/unbans",
      sortTime: toTimestamp(item.createdAt),
    })),
    ...commitments.map((item) => ({
      id: item.id,
      namespace: item.namespace,
      summary: `承诺书已更新，文件 ${item.fileName}`,
      time: item.updatedAt,
      tone: "info" as const,
      targetPath: "/commitments",
      sortTime: toTimestamp(item.updatedAt),
    })),
  ];

  return actions
    .sort((a, b) => b.sortTime - a.sortTime)
    .slice(0, 3)
    .map(({ sortTime: _sortTime, ...item }) => item);
}

function buildNamespaceProfiles(
  violations: ViolationRecord[],
  commitments: CommitmentRecord[],
  bans: BanRecord[],
  unbans: UnbanRecord[],
): NamespaceProfile[] {
  const namespaces = new Set<string>();
  violations.forEach((item) => namespaces.add(item.namespace));
  commitments.forEach((item) => namespaces.add(item.namespace));
  bans.forEach((item) => namespaces.add(item.namespace));
  unbans.forEach((item) => namespaces.add(item.namespace));

  const profiles = [...namespaces].map((namespace) => {
    const namespaceViolations = violations
      .filter((item) => item.namespace === namespace)
      .sort((a, b) => toTimestamp(b.detectedAt) - toTimestamp(a.detectedAt));
    const namespaceCommitment = commitments.find((item) => item.namespace === namespace);
    const namespaceBans = bans
      .filter((item) => item.namespace === namespace)
      .sort((a, b) => toTimestamp(b.banStartTime) - toTimestamp(a.banStartTime));
    const namespaceUnbans = unbans
      .filter((item) => item.namespace === namespace)
      .sort((a, b) => toTimestamp(b.createdAt) - toTimestamp(a.createdAt));

    const timeline: Array<TimelineRecord & { sortTime: number }> = [
      ...namespaceViolations.map((item) => ({
        id: `timeline-${item.id}`,
        title: item.type === "complik" ? "出现内容违规" : "出现进程违规",
        description: summarizeMarkdown(item.description, 72) || "暂无描述",
        time: item.detectedAt,
        tone: getViolationTone(item.type),
        sortTime: toTimestamp(item.detectedAt),
      })),
      ...namespaceBans.map((item) => ({
        id: `timeline-ban-${item.id}`,
        title: "新增封禁记录",
        description: describeBanRecord(item),
        time: item.createdAt,
        tone: "warn" as const,
        sortTime: toTimestamp(item.createdAt),
      })),
      ...namespaceUnbans.map((item) => ({
        id: `timeline-unban-${item.id}`,
        title: "新增解封记录",
        description: `操作人 ${item.operatorName}`,
        time: item.createdAt,
        tone: "success" as const,
        sortTime: toTimestamp(item.createdAt),
      })),
      ...(namespaceCommitment
        ? [
            {
              id: `timeline-commitment-${namespaceCommitment.id}`,
              title: "承诺书已上传",
              description: `${namespaceCommitment.fileName}`,
              time: namespaceCommitment.updatedAt,
              tone: "info" as const,
              sortTime: toTimestamp(namespaceCommitment.updatedAt),
            },
          ]
        : []),
    ].sort((a, b) => b.sortTime - a.sortTime);

    const lastActionAt = timeline[0]?.time ?? "-";

    return {
      namespace,
      violated: namespaceViolations.length > 0,
      banned: namespaceBans.some((item) => item.active),
      commitmentUploaded: Boolean(namespaceCommitment),
      lastActionAt,
      commitment: namespaceCommitment
        ? {
            fileName: namespaceCommitment.fileName,
            fileUrl: namespaceCommitment.fileUrl,
            updatedAt: namespaceCommitment.updatedAt,
          }
        : undefined,
      recentViolations: namespaceViolations.slice(0, 5),
      timeline: timeline.map(({ sortTime: _sortTime, ...item }) => item),
    };
  });

  return profiles.sort((a, b) => a.namespace.localeCompare(b.namespace));
}

export function AppDataProvider({ children }: { children: ReactNode }) {
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [configRecords, setConfigRecords] = useState<ConfigRecord[]>([]);
  const [commitmentRecords, setCommitmentRecords] = useState<CommitmentRecord[]>([]);
  const [banRecords, setBanRecords] = useState<BanRecord[]>([]);
  const [unbanRecords, setUnbanRecords] = useState<UnbanRecord[]>([]);
  const [violations, setViolations] = useState<ViolationRecord[]>([]);

  const refreshAll = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    const safeLoad = async <T,>(loader: () => Promise<T>, fallback: T) => {
      try {
        return await loader();
      } catch (err) {
        return fallback;
      }
    };

    try {
      const [configs, commitments, bans, unbans, violationList] = await Promise.all([
        safeLoad(listConfigRecords, [] as ConfigRecord[]),
        safeLoad(listCommitmentRecords, [] as CommitmentRecord[]),
        safeLoad(listBanRecords, [] as BanRecord[]),
        safeLoad(listUnbanRecords, [] as UnbanRecord[]),
        safeLoad(listViolationRecords, [] as ViolationRecord[]),
      ]);

      setConfigRecords(configs);
      setCommitmentRecords(commitments);
      setBanRecords(bans);
      setUnbanRecords(unbans);
      setViolations(violationList);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载数据失败");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshAll();
  }, [refreshAll]);

  const stats = useMemo(() => buildStats(violations, banRecords, unbanRecords), [banRecords, unbanRecords, violations]);
  const latestViolations = useMemo(() => buildLatestViolations(violations), [violations]);
  const latestActions = useMemo(
    () => buildLatestActions(banRecords, unbanRecords, commitmentRecords),
    [banRecords, commitmentRecords, unbanRecords],
  );
  const namespaceProfiles = useMemo(
    () => buildNamespaceProfiles(violations, commitmentRecords, banRecords, unbanRecords),
    [banRecords, commitmentRecords, unbanRecords, violations],
  );

  const createConfigRecord = useCallback(
    async (input: CreateConfigInput) => {
      await apiCreateConfigRecord(input);
      await refreshAll();
    },
    [refreshAll],
  );

  const updateConfigRecord = useCallback(
    async (configName: string, input: UpdateConfigInput) => {
      await apiUpdateConfigRecord(configName, input);
      await refreshAll();
    },
    [refreshAll],
  );

  const createCommitmentRecord = useCallback(
    async (input: CreateCommitmentInput) => {
      await apiCreateCommitmentRecord(input);
      await refreshAll();
    },
    [refreshAll],
  );

  const createBanRecord = useCallback(
    async (input: CreateBanInput) => {
      await apiCreateBanRecord(input);
      await refreshAll();
    },
    [refreshAll],
  );

  const createUnbanRecord = useCallback(
    async (input: CreateUnbanInput) => {
      await apiCreateUnbanRecord(input);
      await refreshAll();
    },
    [refreshAll],
  );

  const deleteConfigRecord = useCallback(
    async (configName: string) => {
      await apiDeleteConfigRecord(configName);
      await refreshAll();
    },
    [refreshAll],
  );

  const deleteCommitmentRecord = useCallback(
    async (namespace: string) => {
      await apiDeleteCommitmentRecord(namespace);
      await refreshAll();
    },
    [refreshAll],
  );

  const deleteBanRecord = useCallback(
    async (id: number) => {
      await apiDeleteBanRecord(id);
      await refreshAll();
    },
    [refreshAll],
  );

  const deleteUnbanRecord = useCallback(
    async (id: number) => {
      await apiDeleteUnbanRecord(id);
      setUnbanRecords((current) => current.filter((item) => item.apiId !== id));
    },
    [],
  );

  const deleteViolationRecord = useCallback(
    async ({ id, type }: { id: number; type: ViolationRecord["type"] }) => {
      await apiDeleteViolationRecord(id, type);
      await refreshAll();
    },
    [refreshAll],
  );

  const value = useMemo<AppDataContextValue>(
    () => ({
      isLoading,
      error,
      stats,
      latestViolations,
      latestActions,
      quickLinks,
      namespaceProfiles,
      configRecords,
      commitmentRecords,
      banRecords,
      unbanRecords,
      violations,
      refreshAll,
      createConfigRecord,
      updateConfigRecord,
      createCommitmentRecord,
      createBanRecord,
      createUnbanRecord,
      deleteConfigRecord,
      deleteCommitmentRecord,
      deleteBanRecord,
      deleteUnbanRecord,
      deleteViolationRecord,
    }),
    [
      banRecords,
      commitmentRecords,
      configRecords,
      createBanRecord,
      createCommitmentRecord,
      createConfigRecord,
      createUnbanRecord,
      updateConfigRecord,
      deleteBanRecord,
      deleteCommitmentRecord,
      deleteConfigRecord,
      deleteUnbanRecord,
      deleteViolationRecord,
      error,
      isLoading,
      latestActions,
      latestViolations,
      namespaceProfiles,
      refreshAll,
      stats,
      unbanRecords,
      violations,
    ],
  );

  return <AppDataContext.Provider value={value}>{children}</AppDataContext.Provider>;
}

export function useAppData() {
  return useContext(AppDataContext);
}
