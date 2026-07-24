import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { createOpenClawCodingTools } from "../agents/agent-tools.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { resolveOpenClawStateSqlitePath } from "../state/openclaw-state-db.paths.js";
import { buildWorkspaceSkillSnapshot } from "./loading/workspace.js";
import {
  isSealedSkillFilePath,
  readSealedSkillFileSync,
  redactSealedSkillContentFromMessages,
} from "./sealed-runtime.js";
import {
  loadSealedSkillEntries,
  sealConfiguredSkillRoots,
  sealedSkillStoreTestUtils,
} from "./sealed-store.js";

const tempDirs: string[] = [];

function writeSkill(params: {
  skillDir: string;
  name: string;
  description: string;
  body: string;
}): void {
  fs.mkdirSync(params.skillDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    path.join(params.skillDir, "SKILL.md"),
    `---\nname: ${params.name}\ndescription: ${params.description}\n---\n\n${params.body}\n`,
    { mode: 0o600 },
  );
}

function createFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-sealed-skills-"));
  tempDirs.push(root);
  const stateDir = path.join(root, "state-home");
  const sealedRoot = path.join(root, "vendor-skills");
  const skillDir = path.join(sealedRoot, "demo");
  const machineIdPath = path.join(root, "machine-id");
  const canary = "SEALED_SKILL_PLAINTEXT_CANARY_7f6d2";
  fs.writeFileSync(machineIdPath, "0123456789abcdef0123456789abcdef\n", { mode: 0o600 });
  writeSkill({
    skillDir,
    name: "vendor-demo",
    description: "Vendor demo skill",
    body: canary,
  });
  fs.mkdirSync(path.join(skillDir, "references"));
  fs.writeFileSync(path.join(skillDir, "references", "guide.md"), "private guide\n", {
    mode: 0o600,
  });
  const config: OpenClawConfig = { skills: { load: { sealedDirs: [sealedRoot] } } };
  const env = { OPENCLAW_STATE_DIR: stateDir } as NodeJS.ProcessEnv;
  return { canary, config, env, machineIdPath, root, sealedRoot, skillDir, stateDir };
}

async function executeToolText(
  tools: ReturnType<typeof createOpenClawCodingTools>,
  name: string,
  args: Record<string, unknown>,
): Promise<string> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) {
    throw new Error(`Missing ${name} tool`);
  }
  const result = await tool.execute("test-call", args as never);
  return result.content
    .filter((block): block is { type: "text"; text: string } => block.type === "text")
    .map((block) => block.text)
    .join("\n");
}

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
  sealedSkillStoreTestUtils.clearRuntimeIndex();
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe("sealed skill store", () => {
  it.runIf(process.platform === "linux")(
    "seals, verifies, removes, and reloads vendor skill trees by their original paths",
    () => {
      const fixture = createFixture();

      expect(
        sealConfiguredSkillRoots({
          config: fixture.config,
          env: fixture.env,
          machineIdPath: fixture.machineIdPath,
        }),
      ).toEqual({
        configuredRoots: 1,
        sealedRoots: 1,
        restoredRoots: 0,
        removedSkillDirectories: 1,
      });
      expect(fs.existsSync(fixture.skillDir)).toBe(false);

      const entries = loadSealedSkillEntries({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });
      expect(entries).toHaveLength(1);
      expect(entries[0]?.skill).toMatchObject({
        name: "vendor-demo",
        filePath: path.join(fixture.skillDir, "SKILL.md"),
        baseDir: fixture.skillDir,
        storage: { kind: "sealed" },
      });
      const skillPath = path.join(fixture.skillDir, "SKILL.md");
      expect(isSealedSkillFilePath(skillPath)).toBe(true);
      expect(readSealedSkillFileSync(skillPath)?.toString("utf8")).toContain(fixture.canary);
      expect(
        readSealedSkillFileSync(path.join(fixture.skillDir, "references", "guide.md"))?.toString(
          "utf8",
        ),
      ).toBe("private guide\n");

      closeOpenClawStateDatabaseForTest();
      const databasePath = resolveOpenClawStateSqlitePath(fixture.env);
      for (const candidate of [databasePath, `${databasePath}-wal`, `${databasePath}-shm`]) {
        if (fs.existsSync(candidate)) {
          expect(fs.readFileSync(candidate).includes(Buffer.from(fixture.canary))).toBe(false);
        }
      }
    },
  );

  it.runIf(process.platform === "linux")(
    "resumes an interrupted source cleanup without replacing the complete generation",
    () => {
      const fixture = createFixture();
      const secondSkillDir = path.join(fixture.sealedRoot, "second");
      writeSkill({
        skillDir: secondSkillDir,
        name: "vendor-second",
        description: "Second vendor skill",
        body: "second private body",
      });
      sealConfiguredSkillRoots({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });

      sealedSkillStoreTestUtils.resetSourceRemovedMarkerForTest(fixture.sealedRoot, {
        env: fixture.env,
      });
      writeSkill({
        skillDir: fixture.skillDir,
        name: "vendor-demo",
        description: "Partial source left after interruption",
        body: "this must not replace the committed generation",
      });

      expect(
        sealConfiguredSkillRoots({
          config: fixture.config,
          env: fixture.env,
          machineIdPath: fixture.machineIdPath,
        }),
      ).toEqual({
        configuredRoots: 1,
        sealedRoots: 0,
        restoredRoots: 1,
        removedSkillDirectories: 1,
      });
      expect(fs.existsSync(fixture.skillDir)).toBe(false);
      expect(
        loadSealedSkillEntries({
          config: fixture.config,
          env: fixture.env,
          machineIdPath: fixture.machineIdPath,
        }).map((entry) => entry.skill.name),
      ).toEqual(["vendor-demo", "vendor-second"]);
      expect(
        readSealedSkillFileSync(path.join(fixture.skillDir, "SKILL.md"))?.toString("utf8"),
      ).toContain(fixture.canary);
    },
  );

  it.runIf(process.platform === "linux")(
    "keeps the active sealed index during configless skill discovery",
    () => {
      const fixture = createFixture();
      sealConfiguredSkillRoots({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });
      loadSealedSkillEntries({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });

      buildWorkspaceSkillSnapshot(fixture.root);

      expect(
        readSealedSkillFileSync(path.join(fixture.skillDir, "SKILL.md"))?.toString("utf8"),
      ).toContain(fixture.canary);
    },
  );

  it.runIf(process.platform === "linux")(
    "keeps sealed roots read-only before blob readers are installed",
    async () => {
      const fixture = createFixture();
      sealConfiguredSkillRoots({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });
      const tools = createOpenClawCodingTools({
        workspaceDir: fixture.root,
        cwd: fixture.root,
      });

      await expect(
        executeToolText(tools, "write", {
          path: path.join(fixture.skillDir, "replacement.md"),
          content: "no",
        }),
      ).rejects.toMatchObject({ code: "EROFS" });
    },
  );

  it.runIf(process.platform === "linux")(
    "serves sealed paths through host read, ls, find, and grep tools as read-only",
    async () => {
      const fixture = createFixture();
      const hiddenSkillDir = path.join(fixture.sealedRoot, "hidden");
      writeSkill({
        skillDir: hiddenSkillDir,
        name: "vendor-hidden",
        description: "Hidden vendor skill",
        body: "HIDDEN_SEALED_SKILL_CANARY",
      });
      sealConfiguredSkillRoots({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });
      const entries = loadSealedSkillEntries({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });
      const workspaceDir = path.join(fixture.root, "workspace");
      fs.mkdirSync(workspaceDir);
      const ordinaryFile = path.join(workspaceDir, "ordinary.txt");
      fs.writeFileSync(ordinaryFile, "ordinary host file\n");
      const visibleEntries = entries.filter((entry) => entry.skill.name === "vendor-demo");
      const skillsSnapshot = {
        prompt: "",
        skills: visibleEntries.map((entry) => ({ name: entry.skill.name })),
        resolvedSkills: visibleEntries.map((entry) => entry.skill),
      };
      const tools = createOpenClawCodingTools({
        workspaceDir,
        cwd: workspaceDir,
        config: {
          ...fixture.config,
          tools: { profile: "coding", fs: { workspaceOnly: true } },
        },
        skillsSnapshot,
      });

      await expect(
        executeToolText(tools, "read", { path: path.join(fixture.skillDir, "SKILL.md") }),
      ).resolves.toContain(fixture.canary);
      await expect(executeToolText(tools, "read", { path: "@ordinary.txt" })).resolves.toContain(
        "ordinary host file",
      );
      await expect(
        executeToolText(tools, "read", { path: pathToFileURL(ordinaryFile).href }),
      ).resolves.toContain("ordinary host file");
      const readTool = tools.find((tool) => tool.name === "read");
      const sealedSkillPath = path.join(fixture.skillDir, "SKILL.md");
      for (const [index, readPath] of [
        sealedSkillPath,
        `@${sealedSkillPath}`,
        pathToFileURL(sealedSkillPath).href,
        `${sealedSkillPath}</arg_value>>`,
      ].entries()) {
        const toolCallId = `sealed-read-${index}`;
        const readResult = await readTool?.execute(toolCallId, { path: readPath } as never);
        expect(readResult?.details).toMatchObject({ sealedSkillContent: true });
        const diagnosticMessages = redactSealedSkillContentFromMessages([
          {
            role: "assistant",
            content: [
              {
                type: "toolCall",
                id: toolCallId,
                name: "read",
                arguments: { path: readPath },
              },
            ],
          },
          {
            role: "toolResult",
            toolCallId,
            toolName: "read",
            content: readResult?.content ?? [],
            details: readResult?.details,
          },
        ]);
        expect(JSON.stringify(diagnosticMessages)).not.toContain(fixture.canary);
        expect(JSON.stringify(diagnosticMessages)).toContain("omitted from diagnostic output");
      }
      await expect(executeToolText(tools, "ls", { path: fixture.skillDir })).resolves.toContain(
        "SKILL.md",
      );
      await expect(
        executeToolText(tools, "find", { path: fixture.skillDir, pattern: "**/*.md" }),
      ).resolves.toContain("SKILL.md");
      for (const searchPath of [`@${fixture.skillDir}`, pathToFileURL(fixture.skillDir).href]) {
        await expect(
          executeToolText(tools, "find", { path: searchPath, pattern: "**/*.md" }),
        ).resolves.toContain("SKILL.md");
        await expect(
          executeToolText(tools, "grep", { path: searchPath, pattern: fixture.canary }),
        ).resolves.toContain("SKILL.md:6:");
      }
      const grepTool = tools.find((tool) => tool.name === "grep");
      if (!grepTool) {
        throw new Error("Missing grep tool");
      }
      const grepResult = await grepTool.execute("sealed-grep", {
        path: fixture.skillDir,
        pattern: fixture.canary,
      } as never);
      expect(JSON.stringify(grepResult.content)).toContain("SKILL.md:6:");
      expect(grepResult.details).toMatchObject({ sealedSkillContent: true });
      const diagnosticGrepMessages = redactSealedSkillContentFromMessages([
        {
          role: "toolResult",
          toolCallId: "sealed-grep",
          toolName: "grep",
          content: grepResult.content,
          details: grepResult.details,
        },
      ]);
      expect(JSON.stringify(diagnosticGrepMessages)).not.toContain(fixture.canary);
      expect(JSON.stringify(diagnosticGrepMessages)).toContain("omitted from diagnostic output");
      const hiddenSkillPath = path.join(hiddenSkillDir, "SKILL.md");
      for (const readPath of [
        hiddenSkillPath,
        `@${hiddenSkillPath}`,
        pathToFileURL(hiddenSkillPath).href,
      ]) {
        await expect(executeToolText(tools, "read", { path: readPath })).rejects.toThrow(
          /Path escapes (workspace|sandbox) root/,
        );
      }
      for (const [name, args] of [
        ["ls", { path: fixture.root }],
        ["find", { path: fixture.root, pattern: "**/*" }],
        ["grep", { path: fixture.machineIdPath, pattern: "012345" }],
      ] as const) {
        await expect(executeToolText(tools, name, args)).rejects.toThrow(
          /Path escapes (workspace|sandbox) root/,
        );
      }
      const deniedTools = createOpenClawCodingTools({
        workspaceDir,
        cwd: workspaceDir,
        config: {
          ...fixture.config,
          tools: { deny: ["group:fs"] },
        },
        skillsSnapshot,
      });
      expect(deniedTools.map((tool) => tool.name)).not.toEqual(
        expect.arrayContaining(["read", "ls", "find", "grep", "write", "edit"]),
      );
      const unrestrictedTools = createOpenClawCodingTools({
        workspaceDir,
        cwd: workspaceDir,
        skillsSnapshot,
      });
      for (const [name, args] of [
        ["read", { path: hiddenSkillPath }],
        ["ls", { path: hiddenSkillDir }],
        ["find", { path: hiddenSkillDir, pattern: "**/*" }],
        ["grep", { path: hiddenSkillDir, pattern: "HIDDEN" }],
      ] as const) {
        await expect(executeToolText(unrestrictedTools, name, args)).rejects.toThrow(
          /ENOENT|Path not found/,
        );
      }
      await expect(
        executeToolText(unrestrictedTools, "write", {
          path: path.join(fixture.skillDir, "replacement.md"),
          content: "no",
        }),
      ).rejects.toMatchObject({ code: "EROFS" });

      const noSealedSkillsTools = createOpenClawCodingTools({
        workspaceDir,
        cwd: workspaceDir,
        skillsSnapshot: { prompt: "", skills: [], resolvedSkills: [] },
      });
      await expect(
        executeToolText(noSealedSkillsTools, "read", { path: hiddenSkillPath }),
      ).rejects.toMatchObject({ code: "ENOENT" });
      expect(noSealedSkillsTools.map((tool) => tool.name)).not.toEqual(
        expect.arrayContaining(["ls", "find", "grep"]),
      );
    },
  );

  it.runIf(process.platform === "linux")(
    "rejects a state directory that resolves inside the sealed root",
    () => {
      const fixture = createFixture();
      const stateTarget = path.join(fixture.sealedRoot, "state-inside-root");
      const stateAlias = path.join(fixture.root, "state-alias");
      fs.mkdirSync(stateTarget, { mode: 0o700 });
      fs.symlinkSync(stateTarget, stateAlias, "dir");

      expect(() =>
        sealConfiguredSkillRoots({
          config: fixture.config,
          env: { OPENCLAW_STATE_DIR: stateAlias },
          machineIdPath: fixture.machineIdPath,
        }),
      ).toThrow(/must not contain the OpenClaw state directory/);
      expect(fs.existsSync(fixture.skillDir)).toBe(true);
    },
  );

  it.runIf(process.platform === "linux")(
    "keeps the stored generation when the configured source root is empty",
    () => {
      const fixture = createFixture();
      sealConfiguredSkillRoots({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });

      expect(
        sealConfiguredSkillRoots({
          config: fixture.config,
          env: fixture.env,
          machineIdPath: fixture.machineIdPath,
        }),
      ).toEqual({
        configuredRoots: 1,
        sealedRoots: 0,
        restoredRoots: 1,
        removedSkillDirectories: 0,
      });
    },
  );

  it.runIf(process.platform === "linux")("fails closed after machine-id changes", () => {
    const fixture = createFixture();
    sealConfiguredSkillRoots({
      config: fixture.config,
      env: fixture.env,
      machineIdPath: fixture.machineIdPath,
    });
    fs.writeFileSync(fixture.machineIdPath, "fedcba9876543210fedcba9876543210\n");
    sealedSkillStoreTestUtils.clearRuntimeIndex();

    expect(() =>
      loadSealedSkillEntries({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      }),
    ).toThrow(/Cannot decrypt sealed skill root/);
  });

  it.runIf(process.platform === "linux")(
    "replaces an undecryptable completed generation from a reprovisioned source tree",
    () => {
      const fixture = createFixture();
      sealConfiguredSkillRoots({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });
      fs.writeFileSync(fixture.machineIdPath, "fedcba9876543210fedcba9876543210\n");
      writeSkill({
        skillDir: fixture.skillDir,
        name: "vendor-demo",
        description: "Reprovisioned vendor skill",
        body: "REPROVISIONED_SEALED_SKILL_CANARY",
      });

      expect(
        sealConfiguredSkillRoots({
          config: fixture.config,
          env: fixture.env,
          machineIdPath: fixture.machineIdPath,
        }),
      ).toEqual({
        configuredRoots: 1,
        sealedRoots: 1,
        restoredRoots: 0,
        removedSkillDirectories: 1,
      });
      loadSealedSkillEntries({
        config: fixture.config,
        env: fixture.env,
        machineIdPath: fixture.machineIdPath,
      });
      expect(
        readSealedSkillFileSync(path.join(fixture.skillDir, "SKILL.md"))?.toString("utf8"),
      ).toContain("REPROVISIONED_SEALED_SKILL_CANARY");
    },
  );

  it.runIf(process.platform === "linux")(
    "counts nested directories inside discovered skill trees",
    () => {
      const fixture = createFixture();
      const bulkDir = path.join(fixture.skillDir, "bulk");
      for (let index = 0; index < 2_000; index += 1) {
        fs.mkdirSync(path.join(bulkDir, String(index)), { recursive: true });
      }

      expect(() =>
        sealConfiguredSkillRoots({
          config: fixture.config,
          env: fixture.env,
          machineIdPath: fixture.machineIdPath,
        }),
      ).toThrow(/exceeds 2000 directories/);
      expect(fs.existsSync(fixture.skillDir)).toBe(true);
    },
  );

  it.runIf(process.platform === "linux")(
    "refuses executable assets without deleting or committing the source",
    () => {
      const fixture = createFixture();
      const executable = path.join(fixture.skillDir, "run.sh");
      fs.writeFileSync(executable, "#!/bin/sh\n", { mode: 0o700 });

      expect(() =>
        sealConfiguredSkillRoots({
          config: fixture.config,
          env: fixture.env,
          machineIdPath: fixture.machineIdPath,
        }),
      ).toThrow(/do not support executable files/);
      expect(fs.existsSync(fixture.skillDir)).toBe(true);
    },
  );
});
