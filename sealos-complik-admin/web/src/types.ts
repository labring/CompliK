export type RiskTone = "neutral" | "success" | "warn" | "danger" | "info";

export type NavItem = {
  label: string;
  path: string;
};

export type StatCardItem = {
  label: string;
  value: string;
  delta: string;
  tone: RiskTone;
  description: string;
  targetPath?: string;
};

export type ActivityItem = {
  id: string;
  namespace: string;
  summary: string;
  time: string;
  tone: RiskTone;
  targetPath?: string;
};

export type QuickLinkItem = {
  title: string;
  description: string;
  targetPath: string;
};

export type ViolationType = "complik" | "procscan";

export type ViolationRecord = {
  id: string;
  apiId: number;
  type: ViolationType;
  namespace: string;
  detectorName?: string;
  resourceName?: string;
  host?: string;
  url?: string;
  keywords?: string[];
  processName?: string;
  processCommand?: string;
  podName?: string;
  nodeName?: string;
  matchRule?: string;
  labelActionStatus?: string;
  labelActionResult?: string;
  message?: string;
  detectedAt: string;
  description: string;
  rawPayload?: string;
  createdAt?: string;
  updatedAt?: string;
};

export type TimelineRecord = {
  id: string;
  title: string;
  description: string;
  time: string;
  tone: RiskTone;
};

export type NamespaceProfile = {
  namespace: string;
  violated: boolean;
  banned: boolean;
  commitmentUploaded: boolean;
  lastActionAt: string;
  commitment?: {
    fileName: string;
    fileUrl: string;
    updatedAt: string;
  };
  recentViolations: ViolationRecord[];
  timeline: TimelineRecord[];
};

export type ConfigRecord = {
  id: string;
  configName: string;
  configType: string;
  description: string;
  createdAt: string;
  updatedAt: string;
  value: string;
};

export type CommitmentRecord = {
  id: string;
  namespace: string;
  fileName: string;
  fileUrl: string;
  createdAt: string;
  updatedAt: string;
};

export type BanRecord = {
  id: string;
  apiId: number;
  namespace: string;
  reason: string;
  screenshotUrls: string[];
  operatorName: string;
  banStartTime: string;
  banEndTime?: string;
  createdAt: string;
  updatedAt: string;
  active: boolean;
};

export type UnbanRecord = {
  id: string;
  apiId: number;
  namespace: string;
  operatorName: string;
  createdAt: string;
  updatedAt: string;
};

export type CreateConfigInput = {
  configName: string;
  configType: string;
  description: string;
  value: string;
};

export type UpdateConfigInput = CreateConfigInput;

export type CreateCommitmentInput = {
  namespace: string;
  file: File;
};

export type CreateBanInput = {
  namespace: string;
  reason: string;
  operatorName: string;
  banStartTime: string;
  screenshots: File[];
};

export type CreateUnbanInput = {
  namespace: string;
  operatorName: string;
};

export type DeleteViolationInput = {
  id: number;
  type: ViolationType;
};

export type AppDataContextValue = {
  isLoading: boolean;
  error: string | null;
  stats: StatCardItem[];
  latestViolations: ActivityItem[];
  latestActions: ActivityItem[];
  quickLinks: QuickLinkItem[];
  namespaceProfiles: NamespaceProfile[];
  configRecords: ConfigRecord[];
  commitmentRecords: CommitmentRecord[];
  banRecords: BanRecord[];
  unbanRecords: UnbanRecord[];
  violations: ViolationRecord[];
  refreshAll: () => Promise<void>;
  createConfigRecord: (input: CreateConfigInput) => Promise<void>;
  updateConfigRecord: (configName: string, input: UpdateConfigInput) => Promise<void>;
  createCommitmentRecord: (input: CreateCommitmentInput) => Promise<void>;
  createBanRecord: (input: CreateBanInput) => Promise<void>;
  createUnbanRecord: (input: CreateUnbanInput) => Promise<void>;
  deleteConfigRecord: (configName: string) => Promise<void>;
  deleteCommitmentRecord: (namespace: string) => Promise<void>;
  deleteBanRecord: (id: number) => Promise<void>;
  deleteUnbanRecord: (id: number) => Promise<void>;
  deleteViolationRecord: (input: DeleteViolationInput) => Promise<void>;
};
