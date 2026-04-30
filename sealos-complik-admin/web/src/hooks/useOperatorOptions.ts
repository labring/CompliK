import { useMemo } from "react";
import type { ConfigRecord } from "../types";

const OPERATOR_OPTIONS_CONFIG_TYPE = "operator_options";
const OPERATOR_OPTIONS_CONFIG_KEY = "operators";

function normalizeOperatorName(value: string) {
  return value.trim();
}

function normalizeOperatorOptions(values: string[]) {
  const seen = new Set<string>();
  const normalized: string[] = [];

  values.forEach((value) => {
    const operator = normalizeOperatorName(value);
    if (!operator) {
      return;
    }

    const key = operator.toLowerCase();
    if (seen.has(key)) {
      return;
    }

    seen.add(key);
    normalized.push(operator);
  });

  return normalized.sort((left, right) => left.localeCompare(right, "zh-CN"));
}

function parseOperatorOptionsConfig(configRecords: ConfigRecord[]) {
  const record =
    configRecords.find((item) => item.configType === OPERATOR_OPTIONS_CONFIG_TYPE) ??
    configRecords.find((item) => item.configName === OPERATOR_OPTIONS_CONFIG_TYPE);
  if (!record) {
    return [];
  }

  try {
    const parsed = JSON.parse(record.value);
    if (Array.isArray(parsed)) {
      return normalizeOperatorOptions(parsed.filter((item): item is string => typeof item === "string"));
    }

    if (typeof parsed === "object" && parsed !== null && Array.isArray(parsed[OPERATOR_OPTIONS_CONFIG_KEY])) {
      return normalizeOperatorOptions(
        parsed[OPERATOR_OPTIONS_CONFIG_KEY].filter((item): item is string => typeof item === "string"),
      );
    }

    return [];
  } catch {
    return [];
  }
}

export function useManagedOperatorOptions(configRecords: ConfigRecord[], knownOperators: string[]) {
  const configuredOptions = useMemo(() => parseOperatorOptionsConfig(configRecords), [configRecords]);
  const fallbackOptions = useMemo(() => normalizeOperatorOptions(knownOperators), [knownOperators]);

  if (configuredOptions.length > 0) {
    return {
      operatorOptions: configuredOptions,
      operatorSource: "config" as const,
      operatorConfigType: OPERATOR_OPTIONS_CONFIG_TYPE,
    };
  }

  return {
    operatorOptions: fallbackOptions,
    operatorSource: "records" as const,
    operatorConfigType: OPERATOR_OPTIONS_CONFIG_TYPE,
  };
}
