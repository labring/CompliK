import { formatDateTime, toTimestamp } from "./utils";
import type {
  AutobanPolicy,
  BanRecord,
  CommitmentRecord,
  ConfigRecord,
  CreateBanInput,
  CreateCommitmentInput,
  CreateConfigInput,
  UpdateConfigInput,
  CreateUnbanInput,
  CursorPaginatedRecords,
  DiscoveredListQuery,
  DiscoveredPathRecord,
  DiscoveredRouteRecord,
  PaginatedViolationRecords,
  PaginatedRecords,
  RecordListQuery,
  UnbanRecord,
  ViolationListQuery,
  ViolationRecord,
} from "../types";

export const AUTOBAN_POLICY_CONFIG_NAME = "autoban_policy";
export const AUTOBAN_POLICY_CONFIG_TYPE = "autoban_policy";

type ApiErrorPayload = {
  message?: string;
  error?: string;
};

type ProjectConfigDto = {
  config_name: string;
  config_type: string;
  config_value: unknown;
  description?: string;
  created_at: string;
  updated_at: string;
};

type CommitmentDto = {
  namespace: string;
  file_name: string;
  file_url: string;
  created_at: string;
  updated_at: string;
};

type BanDto = {
  id: number;
  namespace: string;
  reason?: string;
  screenshot_urls?: string[];
  ban_start_time: string;
  ban_end_time?: string | null;
  operator_name: string;
  created_at: string;
  updated_at: string;
};

type UnbanDto = {
  id: number;
  namespace: string;
  operator_name: string;
  created_at: string;
  updated_at: string;
};

type ComplikViolationDto = {
  id: number;
  namespace: string;
  detector_name: string;
  resource_name?: string;
  host?: string;
  url?: string;
  device_profile?: string;
  viewport?: string;
  keywords?: string[];
  description?: string;
  is_illegal?: boolean;
  detected_at: string;
  raw_payload?: unknown;
  created_at?: string;
  updated_at?: string;
};

type ProcscanViolationDto = {
  id: number;
  namespace: string;
  pod_name?: string;
  node_name?: string;
  process_name: string;
  process_command: string;
  match_rule?: string;
  label_action_status?: string;
  label_action_result?: string;
  message: string;
  is_illegal?: boolean;
  detected_at: string;
  raw_payload?: unknown;
  created_at?: string;
  updated_at?: string;
};

type DiscoveredRouteDto = {
  namespace: string;
  ingress_name: string;
  host: string;
  path_count: number;
  total_count: number;
  last_seen_at: string;
  last_detected_at?: string | null;
};

type DiscoveredPathDto = {
  id: number;
  namespace: string;
  ingress_name: string;
  host: string;
  path: string;
  count: number;
  last_seen_at: string;
  last_detected_at?: string | null;
  created_at: string;
  updated_at: string;
};

type PaginatedDto<T> = {
  list: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

type CursorPaginatedDto<T> = {
  list: T[] | null;
  next_cursor?: string;
  has_more: boolean;
};

function toPaginatedRecords<TDto, TRecord>(
  data: PaginatedDto<TDto>,
  mapper: (item: TDto) => TRecord,
): PaginatedRecords<TRecord> {
  return {
    list: data.list.map(mapper),
    total: data.total,
    page: data.page,
    pageSize: data.page_size,
    totalPages: data.total_pages,
  };
}

function buildRecordListParams(query: RecordListQuery) {
  const params = new URLSearchParams({
    page: String(query.page),
  });

  const keyword = query.keyword?.trim();
  if (keyword) {
    params.set("keyword", keyword);
  }

  const operatorName = query.operatorName?.trim();
  if (operatorName) {
    params.set("operator_name", operatorName);
  }

  return params;
}

function buildDiscoveredListParams(query: DiscoveredListQuery) {
  const params = new URLSearchParams();

  if (query.cursor) {
    params.set("cursor", query.cursor);
  }

  if (query.limit) {
    params.set("limit", String(query.limit));
  }

  const keyword = query.keyword?.trim();
  if (keyword) {
    params.set("keyword", keyword);
  }

  const namespace = query.namespace?.trim();
  if (namespace) {
    params.set("namespace", namespace);
  }

  const ingressName = query.ingressName?.trim();
  if (ingressName) {
    params.set("ingress_name", ingressName);
  }

  const host = query.host?.trim();
  if (host) {
    params.set("host", host);
  }

  return params;
}

async function request<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  const shouldSetJSONContentType = !(init?.body instanceof FormData);
  if (shouldSetJSONContentType && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(input, {
    headers,
    ...init,
  });

  if (!response.ok) {
    let payload: ApiErrorPayload | null = null;
    try {
      payload = (await response.json()) as ApiErrorPayload;
    } catch {
      payload = null;
    }

    throw new Error(payload?.message ?? payload?.error ?? `请求失败: ${response.status}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

function stringifyJson(value: unknown) {
  if (typeof value === "string") {
    return value;
  }

  return JSON.stringify(value ?? {}, null, 2);
}

function readRecord(value: unknown): Record<string, unknown> | undefined {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function readBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  return undefined;
}

function isComplikIllegal(item: ComplikViolationDto) {
  const rawPayload = readRecord(item.raw_payload);
  const detectorResult = readRecord(rawPayload?.["检测结果"]);
  return (
    readBoolean(detectorResult?.["是否违规"]) ??
    readBoolean(rawPayload?.IsIllegal) ??
    readBoolean(rawPayload?.is_illegal) ??
    item.is_illegal ??
    true
  );
}

function isProcscanIllegal(item: ProcscanViolationDto) {
  const rawPayload = readRecord(item.raw_payload);
  const processInfo = readRecord(rawPayload?.process_info) ?? readRecord(rawPayload?.["进程信息"]);
  return (
    readBoolean(processInfo?.["是否违规"]) ??
    readBoolean(processInfo?.IsIllegal) ??
    readBoolean(processInfo?.is_illegal) ??
    item.is_illegal ??
    true
  );
}

function toConfigRecord(item: ProjectConfigDto): ConfigRecord {
  return {
    id: item.config_name,
    configName: item.config_name,
    configType: item.config_type,
    description: item.description ?? "",
    createdAt: formatDateTime(item.created_at),
    updatedAt: formatDateTime(item.updated_at),
    value: stringifyJson(item.config_value),
  };
}

function toCommitmentRecord(item: CommitmentDto): CommitmentRecord {
  return {
    id: item.namespace,
    namespace: item.namespace,
    fileName: item.file_name,
    fileUrl: item.file_url,
    createdAt: formatDateTime(item.created_at),
    createdAtMs: new Date(item.created_at).getTime(),
    updatedAt: formatDateTime(item.updated_at),
    updatedAtMs: new Date(item.updated_at).getTime(),
  };
}

function toBanRecord(item: BanDto): BanRecord {
  const startAt = new Date(item.ban_start_time).getTime();
  const endAt = item.ban_end_time ? new Date(item.ban_end_time).getTime() : undefined;

  return {
    id: `ban-${item.id}`,
    apiId: item.id,
    namespace: item.namespace,
    reason: item.reason ?? "",
    screenshotUrls: item.screenshot_urls ?? [],
    operatorName: item.operator_name,
    banStartTime: formatDateTime(item.ban_start_time),
    banStartTimeMs: startAt,
    banEndTime: item.ban_end_time ? formatDateTime(item.ban_end_time) : undefined,
    banEndTimeMs: endAt,
    createdAt: formatDateTime(item.created_at),
    createdAtMs: new Date(item.created_at).getTime(),
    updatedAt: formatDateTime(item.updated_at),
  };
}

function toUnbanRecord(item: UnbanDto): UnbanRecord {
  return {
    id: `unban-${item.id}`,
    apiId: item.id,
    namespace: item.namespace,
    operatorName: item.operator_name,
    createdAt: formatDateTime(item.created_at),
    createdAtMs: new Date(item.created_at).getTime(),
    updatedAt: formatDateTime(item.updated_at),
  };
}

function toComplikViolationRecord(item: ComplikViolationDto): ViolationRecord {
  return {
    id: `complik-${item.id}`,
    apiId: item.id,
    type: "complik",
    namespace: item.namespace,
    detectorName: item.detector_name,
    resourceName: item.resource_name,
    host: item.host,
    url: item.url,
    deviceProfile: item.device_profile,
    viewport: item.viewport,
    keywords: item.keywords ?? [],
    detectedAt: formatDateTime(item.detected_at),
    detectedAtMs: new Date(item.detected_at).getTime(),
    description: item.description ?? "暂无说明",
    rawPayload: item.raw_payload ? stringifyJson(item.raw_payload) : undefined,
    createdAt: item.created_at ? formatDateTime(item.created_at) : undefined,
    createdAtMs: item.created_at ? new Date(item.created_at).getTime() : undefined,
    updatedAt: item.updated_at ? formatDateTime(item.updated_at) : undefined,
    updatedAtMs: item.updated_at ? new Date(item.updated_at).getTime() : undefined,
  };
}

function toProcscanViolationRecord(item: ProcscanViolationDto): ViolationRecord {
  return {
    id: `procscan-${item.id}`,
    apiId: item.id,
    type: "procscan",
    namespace: item.namespace,
    processName: item.process_name,
    processCommand: item.process_command,
    podName: item.pod_name,
    nodeName: item.node_name,
    matchRule: item.match_rule,
    labelActionStatus: item.label_action_status,
    labelActionResult: item.label_action_result,
    message: item.message,
    detectedAt: formatDateTime(item.detected_at),
    detectedAtMs: new Date(item.detected_at).getTime(),
    description: item.message,
    rawPayload: item.raw_payload ? stringifyJson(item.raw_payload) : undefined,
    createdAt: item.created_at ? formatDateTime(item.created_at) : undefined,
    createdAtMs: item.created_at ? new Date(item.created_at).getTime() : undefined,
    updatedAt: item.updated_at ? formatDateTime(item.updated_at) : undefined,
    updatedAtMs: item.updated_at ? new Date(item.updated_at).getTime() : undefined,
  };
}

function toDiscoveredRouteRecord(item: DiscoveredRouteDto): DiscoveredRouteRecord {
  const id = `${item.namespace}|${item.ingress_name}|${item.host}`;
  const lastDetectedAtMs = item.last_detected_at ? new Date(item.last_detected_at).getTime() : undefined;

  return {
    id,
    namespace: item.namespace,
    ingressName: item.ingress_name,
    host: item.host,
    pathCount: item.path_count,
    totalCount: item.total_count,
    lastSeenAt: formatDateTime(item.last_seen_at),
    lastSeenAtMs: new Date(item.last_seen_at).getTime(),
    lastDetectedAt: item.last_detected_at ? formatDateTime(item.last_detected_at) : undefined,
    lastDetectedAtMs,
  };
}

function toDiscoveredPathRecord(item: DiscoveredPathDto): DiscoveredPathRecord {
  const lastDetectedAtMs = item.last_detected_at ? new Date(item.last_detected_at).getTime() : undefined;

  return {
    id: `discovered-path-${item.id}`,
    apiId: item.id,
    namespace: item.namespace,
    ingressName: item.ingress_name,
    host: item.host,
    path: item.path,
    count: item.count,
    lastSeenAt: formatDateTime(item.last_seen_at),
    lastSeenAtMs: new Date(item.last_seen_at).getTime(),
    lastDetectedAt: item.last_detected_at ? formatDateTime(item.last_detected_at) : undefined,
    lastDetectedAtMs,
    createdAt: formatDateTime(item.created_at),
    createdAtMs: new Date(item.created_at).getTime(),
    updatedAt: formatDateTime(item.updated_at),
    updatedAtMs: new Date(item.updated_at).getTime(),
  };
}

export async function listConfigRecords() {
  const data = await request<ProjectConfigDto[]>("/api/configs");
  return data.map(toConfigRecord);
}

export async function listConfigRecordsByType(configType: string) {
  const data = await request<ProjectConfigDto[]>(`/api/configs/type/${encodeURIComponent(configType)}`);
  return data.map(toConfigRecord);
}

export async function listConfigRecordsPage(query: RecordListQuery): Promise<PaginatedRecords<ConfigRecord>> {
  const data = await request<PaginatedDto<ProjectConfigDto>>(`/api/configs?${buildRecordListParams(query).toString()}`);
  return toPaginatedRecords(data, toConfigRecord);
}

export async function createConfigRecord(input: CreateConfigInput) {
  await request("/api/configs", {
    method: "POST",
    body: JSON.stringify({
      config_name: input.configName,
      config_type: input.configType,
      description: input.description,
      config_value: JSON.parse(input.value),
    }),
  });
}

export async function deleteConfigRecord(configName: string) {
  await request(`/api/configs/${encodeURIComponent(configName)}`, {
    method: "DELETE",
  });
}

export async function updateConfigRecord(configName: string, input: UpdateConfigInput) {
  await request(`/api/configs/${encodeURIComponent(configName)}`, {
    method: "PUT",
    body: JSON.stringify({
      config_name: input.configName,
      config_type: input.configType,
      description: input.description,
      config_value: JSON.parse(input.value),
    }),
  });
}

export async function saveAutobanPolicy(policy: AutobanPolicy, existingConfigName?: string) {
  const input = {
    configName: AUTOBAN_POLICY_CONFIG_NAME,
    configType: AUTOBAN_POLICY_CONFIG_TYPE,
    description: "Admin automatic namespace ban policy",
    value: JSON.stringify(policy),
  };

  if (existingConfigName) {
    await updateConfigRecord(existingConfigName, input);
    return;
  }

  await createConfigRecord(input);
}

export async function listCommitmentRecords() {
  const data = await request<CommitmentDto[]>("/api/commitments");
  return data.map(toCommitmentRecord);
}

export async function listCommitmentRecordsPage(query: RecordListQuery): Promise<PaginatedRecords<CommitmentRecord>> {
  const data = await request<PaginatedDto<CommitmentDto>>(`/api/commitments?${buildRecordListParams(query).toString()}`);
  return toPaginatedRecords(data, toCommitmentRecord);
}

export async function createCommitmentRecord(input: CreateCommitmentInput) {
  const formData = new FormData();
  formData.set("namespace", input.namespace);
  formData.set("file", input.file);

  try {
    await request("/api/commitments/upload", {
      method: "POST",
      body: formData,
    });
  } catch (error) {
    // Backward compatibility: older backends expose upload at POST /api/commitments.
    if (error instanceof Error && error.message.includes("404")) {
      try {
        await request("/api/commitments", {
          method: "POST",
          body: formData,
        });
        return;
      } catch (legacyError) {
        if (legacyError instanceof Error && legacyError.message.includes("invalid request body")) {
          throw new Error("后端版本过旧：暂不支持承诺书文件上传，请先升级后端服务。");
        }
        throw legacyError;
      }
    }

    throw error;
  }
}

export async function deleteCommitmentRecord(namespace: string) {
  await request(`/api/commitments/${encodeURIComponent(namespace)}`, {
    method: "DELETE",
  });
}

export function buildCommitmentDownloadURL(namespace: string) {
  return `/api/commitments/${encodeURIComponent(namespace)}/download`;
}

export function buildBanScreenshotPreviewURL(fileURL: string) {
  return `/api/bans/screenshots?url=${encodeURIComponent(fileURL)}`;
}

export async function listBanRecords() {
  const data = await request<BanDto[]>("/api/bans");
  return data.map(toBanRecord);
}

export async function listBanRecordsPage(query: RecordListQuery): Promise<PaginatedRecords<BanRecord>> {
  const data = await request<PaginatedDto<BanDto>>(`/api/bans?${buildRecordListParams(query).toString()}`);
  return toPaginatedRecords(data, toBanRecord);
}

export async function createBanRecord(input: CreateBanInput) {
  const screenshots = input.screenshots ?? [];
  if (screenshots.length === 0) {
    await request("/api/bans", {
      method: "POST",
      body: JSON.stringify({
        namespace: input.namespace,
        reason: input.reason,
        operator_name: input.operatorName,
        ban_start_time: new Date(input.banStartTime).toISOString(),
      }),
    });
    return;
  }

  const formData = new FormData();
  formData.set("namespace", input.namespace);
  formData.set("reason", input.reason);
  formData.set("operator_name", input.operatorName);
  formData.set("ban_start_time", new Date(input.banStartTime).toISOString());
  screenshots.forEach((file) => {
    formData.append("screenshots", file);
  });

  try {
    await request("/api/bans/upload", {
      method: "POST",
      body: formData,
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes("404")) {
      try {
        await request("/api/bans", {
          method: "POST",
          body: formData,
        });
        return;
      } catch (legacyError) {
        if (
          legacyError instanceof Error &&
          (legacyError.message.includes("invalid request body") || legacyError.message.includes("invalid form data"))
        ) {
          throw new Error("后端版本较旧，升级后端服务后即可上传封禁截图。");
        }
        throw legacyError;
      }
    }

    throw error;
  }
}

export async function deleteBanRecord(id: number) {
  await request(`/api/bans/id/${id}`, {
    method: "DELETE",
  });
}

export async function listUnbanRecords() {
  const data = await request<UnbanDto[]>("/api/unbans");
  return data.map(toUnbanRecord);
}

export async function listUnbanRecordsPage(query: RecordListQuery): Promise<PaginatedRecords<UnbanRecord>> {
  const data = await request<PaginatedDto<UnbanDto>>(`/api/unbans?${buildRecordListParams(query).toString()}`);
  return toPaginatedRecords(data, toUnbanRecord);
}

export async function createUnbanRecord(input: CreateUnbanInput) {
  await request("/api/unbans", {
    method: "POST",
    body: JSON.stringify({
      namespace: input.namespace,
      operator_name: input.operatorName,
    }),
  });
}

export async function deleteUnbanRecord(id: number) {
  await request(`/api/unbans/id/${id}`, {
    method: "DELETE",
  });
}

export async function listViolationRecords() {
  const [complikData, procscanData] = await Promise.all([
    request<ComplikViolationDto[]>("/api/complik-violations"),
    request<ProcscanViolationDto[]>("/api/procscan-violations"),
  ]);

  return [
    ...complikData.filter(isComplikIllegal).map(toComplikViolationRecord),
    ...procscanData.filter(isProcscanIllegal).map(toProcscanViolationRecord),
  ].sort((a, b) => toTimestamp(b.detectedAt) - toTimestamp(a.detectedAt));
}

export async function listViolationRecordsPage(query: ViolationListQuery): Promise<PaginatedViolationRecords> {
  const params = new URLSearchParams({
    include_all: String(query.scope === "all"),
    page: String(query.page),
    time_range: query.timeRange,
  });

  const keyword = query.keyword.trim();
  if (keyword) {
    params.set("keyword", keyword);
  }

  if (query.type === "complik") {
    const data = await request<PaginatedDto<ComplikViolationDto>>(`/api/complik-violations?${params.toString()}`);
    return toPaginatedRecords(data, toComplikViolationRecord);
  }

  const data = await request<PaginatedDto<ProcscanViolationDto>>(`/api/procscan-violations?${params.toString()}`);
  return toPaginatedRecords(data, toProcscanViolationRecord);
}

export async function deleteViolationRecord(id: number, type: ViolationRecord["type"]) {
  const path = type === "complik" ? "/api/complik-violations" : "/api/procscan-violations";
  await request(`${path}/id/${id}`, {
    method: "DELETE",
  });
}

export async function listDiscoveredRoutes(
  query: DiscoveredListQuery,
): Promise<CursorPaginatedRecords<DiscoveredRouteRecord>> {
  const data = await request<CursorPaginatedDto<DiscoveredRouteDto>>(
    `/api/discovered-routes?${buildDiscoveredListParams(query).toString()}`,
  );

  const list = data.list ?? [];

  return {
    list: list.map(toDiscoveredRouteRecord),
    nextCursor: data.next_cursor,
    hasMore: data.has_more,
  };
}

export async function listDiscoveredPaths(
  query: DiscoveredListQuery,
): Promise<CursorPaginatedRecords<DiscoveredPathRecord>> {
  const data = await request<CursorPaginatedDto<DiscoveredPathDto>>(
    `/api/discovered-paths?${buildDiscoveredListParams(query).toString()}`,
  );

  const list = data.list ?? [];

  return {
    list: list.map(toDiscoveredPathRecord),
    nextCursor: data.next_cursor,
    hasMore: data.has_more,
  };
}

export async function deleteDiscoveredPathRecord(id: number) {
  await request(`/api/discovered-paths/id/${id}`, {
    method: "DELETE",
  });
}
