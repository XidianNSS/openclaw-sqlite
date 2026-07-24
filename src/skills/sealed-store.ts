import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
// Sealed vendor skill storage encrypts immutable skill trees into the shared SQLite database.
import fs from "node:fs";
import path from "node:path";
import { normalizeTrimmedStringList } from "@openclaw/normalization-core/string-normalization";
import type { Insertable, Selectable } from "kysely";
import { z } from "zod";
import { resolveStateDir } from "../config/paths.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { resolvePathViaExistingAncestorSync } from "../infra/boundary-path.js";
import { readRegularFileSync } from "../infra/fs-safe.js";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "../infra/kysely-sync.js";
import { isPathInside } from "../infra/path-guards.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import type { DB as OpenClawStateDatabase } from "../state/openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import {
  parseFrontmatter,
  resolveOpenClawMetadata,
  resolveSkillInvocationPolicy,
} from "./loading/frontmatter.js";
import { loadSkillsFromDirSafe } from "./loading/local-loader.js";
import { createSyntheticSourceInfo, type Skill } from "./loading/skill-contract.js";
import { clearSealedSkillRuntimeIndex, installSealedSkillRuntimeIndex } from "./sealed-runtime.js";
import type { ParsedSkillFrontmatter, SkillEntry } from "./types.js";

const log = createSubsystemLogger("skills/sealed");
const SEALED_SKILL_ALGORITHM = "aes-256-gcm";
const SEALED_SKILL_MANIFEST_VERSION = 1;
const SEALED_SKILL_KDF_INFO = Buffer.from("openclaw:sealed-skills:v1", "utf8");
const DEFAULT_MACHINE_ID_PATH = "/etc/machine-id";
const MAX_MACHINE_ID_BYTES = 128;
const MAX_DISCOVERY_DEPTH = 6;
const MAX_SKILLS_PER_ROOT = 200;
const MAX_DIRECTORIES_PER_ROOT = 2_000;
const MAX_FILES_PER_ROOT = 4_000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;
const MAX_ROOT_BYTES = 128 * 1024 * 1024;

type SealedSkillDatabase = Pick<OpenClawStateDatabase, "sealed_skill_blobs" | "sealed_skill_roots">;
type SealedRootTable = OpenClawStateDatabase["sealed_skill_roots"];
type SealedBlobTable = OpenClawStateDatabase["sealed_skill_blobs"];
type SealedRootRow = Selectable<SealedRootTable>;
type SealedBlobRow = Selectable<SealedBlobTable>;

const frontmatterSchema = z.record(z.string(), z.string());
const manifestFileSchema = z
  .object({
    path: z.string(),
    blobId: z.string(),
    size: z.number().int().nonnegative(),
  })
  .strict();
const manifestSkillSchema = z
  .object({
    name: z.string(),
    description: z.string(),
    filePath: z.string(),
    baseDir: z.string(),
    promptVersion: z.string().optional(),
    frontmatter: frontmatterSchema,
  })
  .strict();
const sealedManifestSchema = z
  .object({
    version: z.literal(SEALED_SKILL_MANIFEST_VERSION),
    rootPath: z.string(),
    generation: z.string(),
    skills: z.array(manifestSkillSchema),
    files: z.array(manifestFileSchema),
  })
  .strict();

type SealedManifest = z.infer<typeof sealedManifestSchema>;
type ManifestSkill = z.infer<typeof manifestSkillSchema>;
type CapturedFile = {
  path: string;
  content: Buffer;
  digest: string;
  blobId: string;
};

type LoadedSealedRoot = {
  manifest: SealedManifest;
  row: SealedRootRow;
  key: Buffer;
  blobs: Map<string, SealedBlobRow>;
};

function sha256Hex(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function normalizeBlob(value: Uint8Array): Buffer {
  return Buffer.isBuffer(value) ? value : Buffer.from(value);
}

function readMachineId(machineIdPath: string): Buffer {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const fd = fs.openSync(machineIdPath, flags);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_MACHINE_ID_BYTES) {
      throw new Error(`Invalid systemd machine-id file: ${machineIdPath}`);
    }
    const raw = fs.readFileSync(fd, "utf8").trim();
    if (!/^[a-f0-9]{32}$/u.test(raw) || /^0+$/u.test(raw)) {
      throw new Error(`Invalid systemd machine-id value in ${machineIdPath}`);
    }
    return Buffer.from(raw, "hex");
  } finally {
    fs.closeSync(fd);
  }
}

function deriveRootKey(machineId: Buffer, salt: Uint8Array): Buffer {
  return Buffer.from(hkdfSync("sha256", machineId, salt, SEALED_SKILL_KDF_INFO, 32));
}

function buildAad(rootKey: string, generation: string, objectId: string): Buffer {
  return Buffer.from(
    `${SEALED_SKILL_MANIFEST_VERSION}\0${rootKey}\0${generation}\0${objectId}`,
    "utf8",
  );
}

function encryptBytes(params: { key: Buffer; plaintext: Buffer; aad: Buffer }): {
  nonce: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
} {
  const nonce = randomBytes(12);
  const cipher = createCipheriv(SEALED_SKILL_ALGORITHM, params.key, nonce);
  cipher.setAAD(params.aad);
  const ciphertext = Buffer.concat([cipher.update(params.plaintext), cipher.final()]);
  return { nonce, tag: cipher.getAuthTag(), ciphertext };
}

function decryptBytes(params: {
  key: Buffer;
  nonce: Uint8Array;
  tag: Uint8Array;
  ciphertext: Uint8Array;
  aad: Buffer;
}): Buffer {
  const decipher = createDecipheriv(
    SEALED_SKILL_ALGORITHM,
    params.key,
    normalizeBlob(params.nonce),
  );
  decipher.setAAD(params.aad);
  decipher.setAuthTag(normalizeBlob(params.tag));
  return Buffer.concat([decipher.update(normalizeBlob(params.ciphertext)), decipher.final()]);
}

function canonicalizePathThroughExistingAncestor(filePath: string): string {
  return path.normalize(resolvePathViaExistingAncestorSync(path.resolve(filePath)));
}

function assertDedicatedRoot(rootPath: string, stateDir: string): void {
  if (!path.isAbsolute(rootPath)) {
    throw new Error(`skills.load.sealedDirs entries must be absolute paths: ${rootPath}`);
  }
  const resolved = path.resolve(rootPath);
  if (resolved === path.parse(resolved).root) {
    throw new Error(`Refusing to seal a filesystem root: ${resolved}`);
  }
  const canonicalRoot = canonicalizePathThroughExistingAncestor(resolved);
  const canonicalStateDir = canonicalizePathThroughExistingAncestor(stateDir);
  if (canonicalRoot === canonicalStateDir || isPathInside(canonicalRoot, canonicalStateDir)) {
    throw new Error(`Sealed skill root must not contain the OpenClaw state directory: ${resolved}`);
  }
  if (isPathInside(canonicalStateDir, canonicalRoot)) {
    throw new Error(
      `Sealed skill root must not be inside the OpenClaw state directory: ${resolved}`,
    );
  }
}

export function resolveConfiguredSealedSkillRoots(
  config?: OpenClawConfig,
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const roots = normalizeTrimmedStringList(config?.skills?.load?.sealedDirs ?? []).map((entry) => {
    assertDedicatedRoot(entry, resolveStateDir(env));
    return path.resolve(entry);
  });
  const unique = Array.from(new Set(roots)).toSorted();
  for (let index = 0; index < unique.length; index += 1) {
    for (let siblingIndex = index + 1; siblingIndex < unique.length; siblingIndex += 1) {
      const left = unique[index];
      const right = unique[siblingIndex];
      if (left && right && (isPathInside(left, right) || isPathInside(right, left))) {
        throw new Error(`Sealed skill roots must not overlap: ${left} and ${right}`);
      }
    }
  }
  return unique;
}

function assertImmutableSourceStat(filePath: string, stat: fs.Stats): void {
  if ((stat.mode & 0o022) !== 0) {
    throw new Error(`Sealed skill sources must not be group- or world-writable: ${filePath}`);
  }
  const currentUid = typeof process.geteuid === "function" ? process.geteuid() : undefined;
  if (stat.uid !== 0 && currentUid !== undefined && stat.uid !== currentUid) {
    throw new Error(`Sealed skill sources must be owned by root or the Gateway user: ${filePath}`);
  }
}

function assertRootDirectory(rootPath: string): string {
  const stat = fs.lstatSync(rootPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Sealed skill root must be a real directory: ${rootPath}`);
  }
  assertImmutableSourceStat(rootPath, stat);
  const realPath = fs.realpathSync(rootPath);
  if (realPath !== path.resolve(rootPath)) {
    throw new Error(`Sealed skill root must not traverse symlinks: ${rootPath} -> ${realPath}`);
  }
  if (fs.existsSync(path.join(rootPath, "SKILL.md"))) {
    throw new Error(
      `Sealed skill roots must contain skill directories, not SKILL.md directly: ${rootPath}`,
    );
  }
  return realPath;
}

function discoverSkillDirectories(rootPath: string): {
  skillDirs: string[];
  directoryCount: number;
} {
  const queue: Array<{ dir: string; depth: number }> = [{ dir: rootPath, depth: 0 }];
  const skills: string[] = [];
  let directoryCount = 0;
  for (const current of queue) {
    const currentStat = fs.lstatSync(current.dir);
    if (!currentStat.isDirectory() || currentStat.isSymbolicLink()) {
      throw new Error(`Sealed skill source must be a real directory: ${current.dir}`);
    }
    assertImmutableSourceStat(current.dir, currentStat);
    directoryCount += 1;
    if (directoryCount > MAX_DIRECTORIES_PER_ROOT) {
      throw new Error(
        `Sealed skill root exceeds ${MAX_DIRECTORIES_PER_ROOT} directories: ${rootPath}`,
      );
    }
    const entries = fs
      .readdirSync(current.dir, { withFileTypes: true })
      .toSorted((a, b) => a.name.localeCompare(b.name));
    const skillFile = entries.find((entry) => entry.name === "SKILL.md");
    if (skillFile) {
      if (!skillFile.isFile() || skillFile.isSymbolicLink()) {
        throw new Error(
          `Sealed SKILL.md must be a regular file: ${path.join(current.dir, "SKILL.md")}`,
        );
      }
      skills.push(current.dir);
      if (skills.length > MAX_SKILLS_PER_ROOT) {
        throw new Error(`Sealed skill root exceeds ${MAX_SKILLS_PER_ROOT} skills: ${rootPath}`);
      }
      continue;
    }
    if (current.depth >= MAX_DISCOVERY_DEPTH) {
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) {
        throw new Error(
          `Sealed skill roots do not allow symlinks: ${path.join(current.dir, entry.name)}`,
        );
      }
      if (!entry.isDirectory() || entry.name.startsWith(".")) {
        continue;
      }
      if (entry.name === "node_modules") {
        throw new Error(
          `Sealed skill roots do not allow node_modules: ${path.join(current.dir, entry.name)}`,
        );
      }
      queue.push({ dir: path.join(current.dir, entry.name), depth: current.depth + 1 });
    }
  }
  return { skillDirs: skills.toSorted(), directoryCount };
}

function captureSkillTree(params: {
  skillDir: string;
  rootPath: string;
  files: CapturedFile[];
  totals: { bytes: number; directories: number; files: number };
}): void {
  const queue = [params.skillDir];
  while (queue.length > 0) {
    const currentDir = queue.shift();
    if (!currentDir) {
      continue;
    }
    for (const entry of fs
      .readdirSync(currentDir, { withFileTypes: true })
      .toSorted((a, b) => a.name.localeCompare(b.name))) {
      const entryPath = path.join(currentDir, entry.name);
      const stat = fs.lstatSync(entryPath);
      if (stat.isSymbolicLink()) {
        throw new Error(`Sealed skills do not allow symlinks: ${entryPath}`);
      }
      if (stat.isDirectory()) {
        assertImmutableSourceStat(entryPath, stat);
        if (entry.name === ".git" || entry.name === "node_modules") {
          throw new Error(`Sealed skills do not allow ${entry.name} directories: ${entryPath}`);
        }
        params.totals.directories += 1;
        if (params.totals.directories > MAX_DIRECTORIES_PER_ROOT) {
          throw new Error(
            `Sealed skill root exceeds ${MAX_DIRECTORIES_PER_ROOT} directories: ${params.rootPath}`,
          );
        }
        queue.push(entryPath);
        continue;
      }
      if (!stat.isFile()) {
        throw new Error(`Sealed skills only allow regular files: ${entryPath}`);
      }
      if (stat.nlink > 1) {
        throw new Error(`Sealed skills do not allow hard-linked files: ${entryPath}`);
      }
      assertImmutableSourceStat(entryPath, stat);
      if ((stat.mode & 0o111) !== 0) {
        throw new Error(`Sealed skills do not support executable files: ${entryPath}`);
      }
      if (stat.size > MAX_FILE_BYTES) {
        throw new Error(`Sealed skill file exceeds ${MAX_FILE_BYTES} bytes: ${entryPath}`);
      }
      const realPath = fs.realpathSync(entryPath);
      if (!isPathInside(params.rootPath, realPath)) {
        throw new Error(`Sealed skill file escapes its configured root: ${entryPath}`);
      }
      const { buffer: content, stat: openedStat } = readRegularFileSync({
        filePath: entryPath,
        maxBytes: MAX_FILE_BYTES,
      });
      if (openedStat.nlink > 1) {
        throw new Error(`Sealed skills do not allow hard-linked files: ${entryPath}`);
      }
      assertImmutableSourceStat(entryPath, openedStat);
      if ((openedStat.mode & 0o111) !== 0) {
        throw new Error(`Sealed skills do not support executable files: ${entryPath}`);
      }
      params.totals.files += 1;
      params.totals.bytes += content.byteLength;
      if (params.totals.files > MAX_FILES_PER_ROOT || params.totals.bytes > MAX_ROOT_BYTES) {
        throw new Error(`Sealed skill root exceeds its file or byte budget: ${params.rootPath}`);
      }
      params.files.push({
        path: realPath,
        content,
        digest: sha256Hex(content),
        blobId: randomBytes(16).toString("hex"),
      });
    }
  }
}

function captureRoot(rootPath: string): {
  generation: string;
  skills: ManifestSkill[];
  files: CapturedFile[];
} {
  const rootRealPath = assertRootDirectory(rootPath);
  const discovery = discoverSkillDirectories(rootRealPath);
  const skillDirs = discovery.skillDirs;
  if (skillDirs.length === 0) {
    return { generation: "", skills: [], files: [] };
  }
  const files: CapturedFile[] = [];
  const skills: ManifestSkill[] = [];
  const totals = { bytes: 0, directories: discovery.directoryCount, files: 0 };
  for (const skillDir of skillDirs) {
    const loaded = loadSkillsFromDirSafe({ dir: skillDir, source: "openclaw-sealed" });
    const skill = loaded.skills.find((candidate) => path.resolve(candidate.baseDir) === skillDir);
    if (!skill) {
      throw new Error(`Sealed skill has invalid or missing frontmatter: ${skillDir}`);
    }
    const frontmatter =
      loaded.frontmatterByFilePath.get(skill.filePath) ??
      parseFrontmatter(
        readRegularFileSync({ filePath: skill.filePath, maxBytes: MAX_FILE_BYTES }).buffer.toString(
          "utf8",
        ),
      );
    skills.push({
      name: skill.name,
      description: skill.description,
      filePath: skill.filePath,
      baseDir: skill.baseDir,
      ...(skill.promptVersion ? { promptVersion: skill.promptVersion } : {}),
      frontmatter,
    });
    captureSkillTree({ skillDir, rootPath: rootRealPath, files, totals });
  }
  const generationHash = createHash("sha256");
  for (const file of files.toSorted((left, right) => left.path.localeCompare(right.path))) {
    generationHash.update(path.relative(rootRealPath, file.path));
    generationHash.update("\0");
    generationHash.update(file.digest);
    generationHash.update("\0");
  }
  return { generation: generationHash.digest("hex"), skills, files };
}

function getSealedKysely(db: import("node:sqlite").DatabaseSync) {
  return getNodeSqliteKysely<SealedSkillDatabase>(db);
}

function selectRootRow(
  rootPath: string,
  options: OpenClawStateDatabaseOptions = {},
): SealedRootRow | undefined {
  const database = openOpenClawStateDatabase(options);
  return executeSqliteQueryTakeFirstSync(
    database.db,
    getSealedKysely(database.db)
      .selectFrom("sealed_skill_roots")
      .selectAll()
      .where("root_path", "=", rootPath),
  );
}

function loadRoot(params: {
  row: SealedRootRow;
  machineId: Buffer;
  options?: OpenClawStateDatabaseOptions;
}): LoadedSealedRoot {
  if (params.row.algorithm !== SEALED_SKILL_ALGORITHM) {
    throw new Error(`Unsupported sealed skill algorithm for ${params.row.root_path}`);
  }
  const key = deriveRootKey(params.machineId, params.row.kdf_salt);
  let manifestRaw: Buffer;
  try {
    manifestRaw = decryptBytes({
      key,
      nonce: params.row.manifest_nonce,
      tag: params.row.manifest_tag,
      ciphertext: params.row.manifest_ciphertext,
      aad: buildAad(params.row.root_key, params.row.generation, "manifest"),
    });
  } catch (error) {
    throw new Error(`Cannot decrypt sealed skill root ${params.row.root_path}`, { cause: error });
  }
  const manifest = sealedManifestSchema.parse(JSON.parse(manifestRaw.toString("utf8")) as unknown);
  if (manifest.rootPath !== params.row.root_path || manifest.generation !== params.row.generation) {
    throw new Error(`Sealed skill manifest identity mismatch for ${params.row.root_path}`);
  }
  validateManifestPaths(manifest);
  const database = openOpenClawStateDatabase(params.options);
  const rows = executeSqliteQuerySync(
    database.db,
    getSealedKysely(database.db)
      .selectFrom("sealed_skill_blobs")
      .selectAll()
      .where("root_key", "=", params.row.root_key)
      .where("generation", "=", params.row.generation),
  ).rows;
  const blobs = new Map(rows.map((row) => [row.blob_id, row]));
  if (blobs.size !== manifest.files.length) {
    throw new Error(`Sealed skill blob count mismatch for ${params.row.root_path}`);
  }
  for (const file of manifest.files) {
    if (!blobs.has(file.blobId)) {
      throw new Error(`Sealed skill blob is missing for ${file.path}`);
    }
  }
  return { manifest, row: params.row, key, blobs };
}

function validateManifestPaths(manifest: SealedManifest): void {
  const rootPath = path.resolve(manifest.rootPath);
  const filePaths = new Set<string>();
  const blobIds = new Set<string>();
  for (const file of manifest.files) {
    const filePath = path.resolve(file.path);
    if (file.path !== filePath || !isPathInside(rootPath, filePath)) {
      throw new Error(`Sealed skill manifest file escapes ${rootPath}: ${file.path}`);
    }
    if (filePaths.has(filePath) || blobIds.has(file.blobId)) {
      throw new Error(`Sealed skill manifest contains duplicate file identities: ${file.path}`);
    }
    filePaths.add(filePath);
    blobIds.add(file.blobId);
  }
  for (const skill of manifest.skills) {
    const baseDir = path.resolve(skill.baseDir);
    const filePath = path.resolve(skill.filePath);
    if (
      skill.baseDir !== baseDir ||
      skill.filePath !== filePath ||
      !isPathInside(rootPath, baseDir) ||
      filePath !== path.join(baseDir, "SKILL.md") ||
      !filePaths.has(filePath)
    ) {
      throw new Error(`Sealed skill manifest contains an invalid skill path: ${skill.filePath}`);
    }
  }
}

function verifyLoadedRoot(root: LoadedSealedRoot): void {
  for (const file of root.manifest.files) {
    const blob = root.blobs.get(file.blobId);
    if (!blob) {
      throw new Error(`Sealed skill blob is missing for ${file.path}`);
    }
    const plaintext = decryptBytes({
      key: root.key,
      nonce: blob.nonce,
      tag: blob.auth_tag,
      ciphertext: blob.ciphertext,
      aad: buildAad(root.row.root_key, root.row.generation, blob.blob_id),
    });
    if (plaintext.byteLength !== file.size) {
      throw new Error(`Sealed skill blob size mismatch for ${file.path}`);
    }
  }
}

function persistCapturedRoot(params: {
  rootPath: string;
  capture: ReturnType<typeof captureRoot>;
  machineId: Buffer;
  options?: OpenClawStateDatabaseOptions;
}): void {
  const rootKey = sha256Hex(params.rootPath);
  const salt = randomBytes(32);
  const key = deriveRootKey(params.machineId, salt);
  const manifest: SealedManifest = {
    version: SEALED_SKILL_MANIFEST_VERSION,
    rootPath: params.rootPath,
    generation: params.capture.generation,
    skills: params.capture.skills,
    files: params.capture.files.map((file) => ({
      path: file.path,
      blobId: file.blobId,
      size: file.content.byteLength,
    })),
  };
  const encryptedManifest = encryptBytes({
    key,
    plaintext: Buffer.from(JSON.stringify(manifest), "utf8"),
    aad: buildAad(rootKey, params.capture.generation, "manifest"),
  });
  const encryptedFiles = params.capture.files.map((file) => ({
    file,
    encrypted: encryptBytes({
      key,
      plaintext: file.content,
      aad: buildAad(rootKey, params.capture.generation, file.blobId),
    }),
  }));
  const database = openOpenClawStateDatabase(params.options);
  database.db.exec("PRAGMA synchronous = FULL;");
  try {
    runOpenClawStateWriteTransaction(({ db }) => {
      const kysely = getSealedKysely(db);
      const rootRow: Insertable<SealedRootTable> = {
        root_key: rootKey,
        root_path: params.rootPath,
        generation: params.capture.generation,
        algorithm: SEALED_SKILL_ALGORITHM,
        kdf_salt: salt,
        manifest_nonce: encryptedManifest.nonce,
        manifest_tag: encryptedManifest.tag,
        manifest_ciphertext: encryptedManifest.ciphertext,
        sealed_at: Date.now(),
        source_removed_at: null,
      };
      executeSqliteQuerySync(
        db,
        kysely
          .insertInto("sealed_skill_roots")
          .values(rootRow)
          .onConflict((conflict) =>
            conflict.column("root_key").doUpdateSet({
              root_path: (eb) => eb.ref("excluded.root_path"),
              generation: (eb) => eb.ref("excluded.generation"),
              algorithm: (eb) => eb.ref("excluded.algorithm"),
              kdf_salt: (eb) => eb.ref("excluded.kdf_salt"),
              manifest_nonce: (eb) => eb.ref("excluded.manifest_nonce"),
              manifest_tag: (eb) => eb.ref("excluded.manifest_tag"),
              manifest_ciphertext: (eb) => eb.ref("excluded.manifest_ciphertext"),
              sealed_at: (eb) => eb.ref("excluded.sealed_at"),
              source_removed_at: null,
            }),
          ),
      );
      executeSqliteQuerySync(
        db,
        kysely.deleteFrom("sealed_skill_blobs").where("root_key", "=", rootKey),
      );
      for (const item of encryptedFiles) {
        const blobRow: Insertable<SealedBlobTable> = {
          root_key: rootKey,
          generation: params.capture.generation,
          blob_id: item.file.blobId,
          nonce: item.encrypted.nonce,
          auth_tag: item.encrypted.tag,
          ciphertext: item.encrypted.ciphertext,
        };
        executeSqliteQuerySync(db, kysely.insertInto("sealed_skill_blobs").values(blobRow));
      }
    }, params.options);
  } finally {
    database.db.exec("PRAGMA synchronous = NORMAL;");
  }
  const stored = selectRootRow(params.rootPath, params.options);
  if (!stored) {
    throw new Error(`Sealed skill root was not committed: ${params.rootPath}`);
  }
  verifyLoadedRoot(loadRoot({ row: stored, machineId: params.machineId, options: params.options }));
}

function removeCapturedSkillSources(rootPath: string, skills: readonly ManifestSkill[]): number {
  const baseDirs = Array.from(new Set(skills.map((skill) => skill.baseDir))).toSorted(
    (left, right) => right.length - left.length,
  );
  let removed = 0;
  for (const baseDir of baseDirs) {
    const resolved = path.resolve(baseDir);
    if (!isPathInside(rootPath, resolved)) {
      throw new Error(`Refusing to remove sealed skill source outside ${rootPath}: ${resolved}`);
    }
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(resolved);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        continue;
      }
      throw error;
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`Refusing to remove replaced sealed skill source: ${resolved}`);
    }
    assertImmutableSourceStat(resolved, stat);
    const realPath = fs.realpathSync(resolved);
    if (realPath !== resolved || !isPathInside(rootPath, realPath)) {
      throw new Error(`Refusing to remove aliased sealed skill source: ${resolved}`);
    }
    fs.rmSync(resolved, { recursive: true, force: false });
    removed += 1;
  }
  return removed;
}

function markSourceRemoved(
  rootPath: string,
  options: OpenClawStateDatabaseOptions | undefined,
): void {
  runOpenClawStateWriteTransaction(({ db }) => {
    executeSqliteQuerySync(
      db,
      getSealedKysely(db)
        .updateTable("sealed_skill_roots")
        .set({ source_removed_at: Date.now() })
        .where("root_path", "=", rootPath),
    );
  }, options);
}

function resetSourceRemovedMarkerForTest(
  rootPath: string,
  options: OpenClawStateDatabaseOptions,
): void {
  runOpenClawStateWriteTransaction(({ db }) => {
    executeSqliteQuerySync(
      db,
      getSealedKysely(db)
        .updateTable("sealed_skill_roots")
        .set({ source_removed_at: null })
        .where("root_path", "=", rootPath),
    );
  }, options);
}

function clearRuntimeIndex(): void {
  clearSealedSkillRuntimeIndex();
}

function assertIncompleteRemovalContainsNoUnknownSkills(root: LoadedSealedRoot): void {
  if (!fs.existsSync(root.manifest.rootPath)) {
    return;
  }
  const expected = new Set(root.manifest.skills.map((skill) => path.resolve(skill.baseDir)));
  for (const discovered of discoverSkillDirectories(root.manifest.rootPath).skillDirs) {
    if (!expected.has(path.resolve(discovered))) {
      throw new Error(
        `Incomplete sealed skill cleanup found an uncommitted skill directory: ${discovered}`,
      );
    }
  }
}

export type SealConfiguredSkillRootsResult = {
  configuredRoots: number;
  sealedRoots: number;
  restoredRoots: number;
  removedSkillDirectories: number;
};

export function sealConfiguredSkillRoots(params: {
  config?: OpenClawConfig;
  env?: NodeJS.ProcessEnv;
  machineIdPath?: string;
  platform?: NodeJS.Platform;
  databasePath?: string;
}): SealConfiguredSkillRootsResult {
  const env = params.env ?? process.env;
  const roots = resolveConfiguredSealedSkillRoots(params.config, env);
  if (roots.length === 0) {
    clearRuntimeIndex();
    return { configuredRoots: 0, sealedRoots: 0, restoredRoots: 0, removedSkillDirectories: 0 };
  }
  if ((params.platform ?? process.platform) !== "linux") {
    throw new Error("skills.load.sealedDirs is supported only on Linux systemd hosts.");
  }
  const machineId = readMachineId(params.machineIdPath ?? DEFAULT_MACHINE_ID_PATH);
  const options: OpenClawStateDatabaseOptions = {
    env,
    ...(params.databasePath ? { path: params.databasePath } : {}),
  };
  if (params.databasePath) {
    for (const rootPath of roots) {
      assertDedicatedRoot(rootPath, path.dirname(params.databasePath));
    }
  }
  let sealedRoots = 0;
  let restoredRoots = 0;
  let removedSkillDirectories = 0;
  for (const rootPath of roots) {
    const existing = selectRootRow(rootPath, options);
    let capturedSource: ReturnType<typeof captureRoot> | undefined;
    if (existing && existing.source_removed_at !== null && fs.existsSync(rootPath)) {
      capturedSource = captureRoot(rootPath);
      if (capturedSource.skills.length > 0) {
        // A complete reprovisioned source tree is the recovery boundary when
        // machine identity changes make the previous generation undecryptable.
        persistCapturedRoot({ rootPath, capture: capturedSource, machineId, options });
        removedSkillDirectories += removeCapturedSkillSources(rootPath, capturedSource.skills);
        markSourceRemoved(rootPath, options);
        sealedRoots += 1;
        log.info(`sealed ${capturedSource.skills.length} vendor skill(s) from ${rootPath}`);
        continue;
      }
    }
    const loadedExisting = existing ? loadRoot({ row: existing, machineId, options }) : undefined;
    if (loadedExisting) {
      verifyLoadedRoot(loadedExisting);
    }
    if (loadedExisting && existing?.source_removed_at === null) {
      // The encrypted generation committed before source cleanup. Resume that exact
      // cleanup instead of replacing it with whatever subset survived the interruption.
      assertIncompleteRemovalContainsNoUnknownSkills(loadedExisting);
      removedSkillDirectories += removeCapturedSkillSources(
        rootPath,
        loadedExisting.manifest.skills,
      );
      markSourceRemoved(rootPath, options);
      restoredRoots += 1;
      continue;
    }
    if (!fs.existsSync(rootPath)) {
      if (!loadedExisting) {
        throw new Error(
          `Configured sealed skill root is missing and has no stored generation: ${rootPath}`,
        );
      }
      restoredRoots += 1;
      continue;
    }
    const capture = capturedSource ?? captureRoot(rootPath);
    if (capture.skills.length === 0) {
      if (!loadedExisting) {
        throw new Error(`Configured sealed skill root contains no skills: ${rootPath}`);
      }
      restoredRoots += 1;
      continue;
    }
    persistCapturedRoot({ rootPath, capture, machineId, options });
    removedSkillDirectories += removeCapturedSkillSources(rootPath, capture.skills);
    markSourceRemoved(rootPath, options);
    sealedRoots += 1;
    log.info(`sealed ${capture.skills.length} vendor skill(s) from ${rootPath}`);
  }
  // Keep configured root identities active immediately so host mutation tools
  // cannot write into sealed roots before skill discovery installs blob readers.
  installSealedSkillRuntimeIndex({ readersByPath: new Map(), rootPaths: new Set(roots) });
  return { configuredRoots: roots.length, sealedRoots, restoredRoots, removedSkillDirectories };
}

function loadConfiguredRoots(params: {
  config?: OpenClawConfig;
  env?: NodeJS.ProcessEnv;
  machineIdPath?: string;
  platform?: NodeJS.Platform;
  databasePath?: string;
}): LoadedSealedRoot[] {
  const env = params.env ?? process.env;
  const roots = resolveConfiguredSealedSkillRoots(params.config, env);
  if (roots.length === 0) {
    return [];
  }
  if ((params.platform ?? process.platform) !== "linux") {
    throw new Error("skills.load.sealedDirs is supported only on Linux systemd hosts.");
  }
  const machineId = readMachineId(params.machineIdPath ?? DEFAULT_MACHINE_ID_PATH);
  const options: OpenClawStateDatabaseOptions = {
    env,
    ...(params.databasePath ? { path: params.databasePath } : {}),
  };
  return roots.map((rootPath) => {
    const row = selectRootRow(rootPath, options);
    if (!row) {
      throw new Error(`Configured sealed skill root has no stored generation: ${rootPath}`);
    }
    return loadRoot({ row, machineId, options });
  });
}

function skillFromManifest(root: LoadedSealedRoot, skill: ManifestSkill): SkillEntry {
  const invocation = resolveSkillInvocationPolicy(skill.frontmatter as ParsedSkillFrontmatter);
  const loadedSkill: Skill = {
    name: skill.name,
    description: skill.description,
    filePath: skill.filePath,
    baseDir: skill.baseDir,
    ...(skill.promptVersion ? { promptVersion: skill.promptVersion } : {}),
    source: "openclaw-sealed",
    sourceInfo: createSyntheticSourceInfo(skill.filePath, {
      source: "openclaw-sealed",
      baseDir: skill.baseDir,
      scope: "project",
      origin: "top-level",
    }),
    disableModelInvocation: invocation.disableModelInvocation,
    storage: {
      kind: "sealed",
      rootKey: root.row.root_key,
      generation: root.row.generation,
    },
  };
  return {
    skill: loadedSkill,
    frontmatter: skill.frontmatter,
    metadata: resolveOpenClawMetadata(skill.frontmatter),
    invocation,
    exposure: {
      includeInRuntimeRegistry: true,
      includeInAvailableSkillsPrompt: !invocation.disableModelInvocation,
      userInvocable: invocation.userInvocable,
    },
  };
}

export function loadSealedSkillEntries(params: {
  config?: OpenClawConfig;
  env?: NodeJS.ProcessEnv;
  machineIdPath?: string;
  platform?: NodeJS.Platform;
  databasePath?: string;
}): SkillEntry[] {
  const roots = loadConfiguredRoots(params);
  const readersByPath = new Map<string, () => Buffer>();
  const rootPaths = new Set<string>();
  const entries: SkillEntry[] = [];
  for (const root of roots) {
    rootPaths.add(root.manifest.rootPath);
    for (const file of root.manifest.files) {
      const blob = root.blobs.get(file.blobId);
      if (!blob) {
        throw new Error(`Sealed skill blob is missing for ${file.path}`);
      }
      const filePath = path.resolve(file.path);
      readersByPath.set(filePath, () => {
        try {
          return decryptBytes({
            key: root.key,
            nonce: blob.nonce,
            tag: blob.auth_tag,
            ciphertext: blob.ciphertext,
            aad: buildAad(blob.root_key, blob.generation, blob.blob_id),
          });
        } catch (error) {
          throw new Error(`Cannot decrypt sealed skill file ${filePath}`, { cause: error });
        }
      });
    }
    entries.push(...root.manifest.skills.map((skill) => skillFromManifest(root, skill)));
  }
  installSealedSkillRuntimeIndex({ readersByPath, rootPaths });
  return entries.toSorted((left, right) => left.skill.name.localeCompare(right.skill.name, "en"));
}

export const sealedSkillStoreTestUtils = {
  clearRuntimeIndex,
  resetSourceRemovedMarkerForTest,
};
