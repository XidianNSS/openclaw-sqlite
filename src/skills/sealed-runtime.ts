// Process-local virtual filesystem for encrypted skill resources.
import path from "node:path";
import { isPathInside } from "../infra/path-guards.js";
import type { Skill } from "./loading/skill-contract.js";

type SealedRuntimeIndex = {
  readersByPath: Map<string, () => Buffer>;
  directoriesByPath: Map<string, Set<string>>;
  rootPaths: Set<string>;
};

function createEmptyRuntimeIndex(): SealedRuntimeIndex {
  return {
    readersByPath: new Map(),
    directoriesByPath: new Map(),
    rootPaths: new Set(),
  };
}

let runtimeIndex = createEmptyRuntimeIndex();

export function clearSealedSkillRuntimeIndex(): void {
  runtimeIndex = createEmptyRuntimeIndex();
}

export function hasSealedSkillRuntime(): boolean {
  return runtimeIndex.rootPaths.size > 0;
}

export function installSealedSkillRuntimeIndex(params: {
  readersByPath: Map<string, () => Buffer>;
  rootPaths: Set<string>;
}): void {
  const nextIndex = createEmptyRuntimeIndex();
  for (const rootPath of params.rootPaths) {
    nextIndex.rootPaths.add(rootPath);
    nextIndex.directoriesByPath.set(rootPath, new Set());
  }
  for (const [rawFilePath, reader] of params.readersByPath) {
    const filePath = path.resolve(rawFilePath);
    const rootPath = Array.from(nextIndex.rootPaths).find((candidate) =>
      isPathInside(candidate, filePath),
    );
    if (!rootPath) {
      throw new Error(`Sealed skill file has no runtime root: ${filePath}`);
    }
    nextIndex.readersByPath.set(filePath, reader);
    let childPath = filePath;
    for (let parentPath = path.dirname(filePath); ; parentPath = path.dirname(parentPath)) {
      const entries = nextIndex.directoriesByPath.get(parentPath) ?? new Set<string>();
      entries.add(path.basename(childPath));
      nextIndex.directoriesByPath.set(parentPath, entries);
      if (parentPath === rootPath) {
        break;
      }
      if (!isPathInside(rootPath, parentPath)) {
        throw new Error(`Sealed skill file escapes its runtime root: ${filePath}`);
      }
      childPath = parentPath;
    }
  }
  runtimeIndex = nextIndex;
}

export function isSealedSkill(skill: Skill): boolean {
  return skill.storage?.kind === "sealed";
}

export function isSealedSkillFilePath(filePath: string): boolean {
  return runtimeIndex.readersByPath.has(path.resolve(filePath));
}

export function isPathInsideSealedSkillRoot(filePath: string): boolean {
  const resolved = path.resolve(filePath);
  return Array.from(runtimeIndex.rootPaths).some(
    (rootPath) => resolved === rootPath || isPathInside(rootPath, resolved),
  );
}

export function readSealedSkillFileSync(filePath: string): Buffer | undefined {
  const reader = runtimeIndex.readersByPath.get(path.resolve(filePath));
  return reader?.();
}

export function getSealedSkillPathKind(filePath: string): "file" | "directory" | undefined {
  const resolved = path.resolve(filePath);
  if (runtimeIndex.readersByPath.has(resolved)) {
    return "file";
  }
  if (runtimeIndex.directoriesByPath.has(resolved)) {
    return "directory";
  }
  return undefined;
}

export function listSealedSkillDirectorySync(dirPath: string): string[] | undefined {
  const entries = runtimeIndex.directoriesByPath.get(path.resolve(dirPath));
  return entries ? Array.from(entries).toSorted() : undefined;
}

export function findSealedSkillFilesSync(params: {
  searchPath: string;
  pattern: string;
  limit: number;
}): string[] | undefined {
  const searchPath = path.resolve(params.searchPath);
  if (!isPathInsideSealedSkillRoot(searchPath)) {
    return undefined;
  }
  if (getSealedSkillPathKind(searchPath) !== "directory") {
    return [];
  }
  const matches: string[] = [];
  for (const filePath of runtimeIndex.readersByPath.keys()) {
    if (!isPathInside(searchPath, filePath)) {
      continue;
    }
    const relativePath = path.relative(searchPath, filePath).split(path.sep).join("/");
    const patternMatches = params.pattern.includes("/")
      ? path.matchesGlob(relativePath, params.pattern)
      : path.matchesGlob(path.posix.basename(relativePath), params.pattern);
    if (patternMatches) {
      matches.push(filePath);
      if (matches.length >= params.limit) {
        break;
      }
    }
  }
  return matches.toSorted();
}

export function listSealedSkillFilesSync(searchPath: string): string[] | undefined {
  const resolved = path.resolve(searchPath);
  if (!isPathInsideSealedSkillRoot(resolved)) {
    return undefined;
  }
  if (getSealedSkillPathKind(resolved) === "file") {
    return [resolved];
  }
  if (getSealedSkillPathKind(resolved) !== "directory") {
    return [];
  }
  return Array.from(runtimeIndex.readersByPath.keys())
    .filter((filePath) => isPathInside(resolved, filePath))
    .toSorted();
}

const SEALED_DIAGNOSTIC_REDACTION_TEXT = "[Sealed skill content omitted from diagnostic output.]";

function isMarkedSealedToolResult(message: Record<string, unknown>): boolean {
  const details = message.details;
  return Boolean(
    details &&
    typeof details === "object" &&
    (details as Record<string, unknown>).sealedSkillContent === true,
  );
}

function sealedReadToolCallIds(message: Record<string, unknown>): string[] {
  if (message.role !== "assistant" || !Array.isArray(message.content)) {
    return [];
  }
  const ids: string[] = [];
  for (const block of message.content) {
    if (!block || typeof block !== "object") {
      continue;
    }
    const call = block as Record<string, unknown>;
    if (typeof call.name !== "string" || call.name.toLowerCase() !== "read") {
      continue;
    }
    const args = call.arguments ?? call.input ?? call.parameters;
    if (!args || typeof args !== "object") {
      continue;
    }
    const argsRecord = args as Record<string, unknown>;
    const filePath = argsRecord.path ?? argsRecord.file_path ?? argsRecord.filePath;
    if (
      typeof filePath === "string" &&
      (isSealedSkillFilePath(filePath) || isPathInsideSealedSkillRoot(filePath)) &&
      typeof call.id === "string"
    ) {
      ids.push(call.id);
    }
  }
  return ids;
}

/** Redact sealed read bodies from diagnostic copies without changing live model messages. */
export function redactSealedSkillContentFromMessages<T>(messages: readonly T[]): T[] {
  const sealedCallIds = new Set<string>();
  return messages.map((message) => {
    if (!message || typeof message !== "object") {
      return message;
    }
    const record = message as Record<string, unknown>;
    const callIds = sealedReadToolCallIds(record);
    if (callIds.length > 0) {
      for (const callId of callIds) {
        sealedCallIds.add(callId);
      }
      return message;
    }
    const toolCallId = typeof record.toolCallId === "string" ? record.toolCallId : undefined;
    if (
      record.role !== "toolResult" ||
      (!isMarkedSealedToolResult(record) && (!toolCallId || !sealedCallIds.has(toolCallId)))
    ) {
      return message;
    }
    return {
      ...record,
      content: [{ type: "text", text: SEALED_DIAGNOSTIC_REDACTION_TEXT }],
    } as unknown as T;
  });
}
