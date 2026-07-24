import path from "node:path";
import { describe, expect, it } from "vitest";
import { OpenClawSchema } from "./zod-schema.js";

describe("skills config schema", () => {
  it("requires sealed skill roots to be non-empty absolute paths", () => {
    for (const sealedDir of ["", "relative/vendor-skills"]) {
      expect(
        OpenClawSchema.safeParse({ skills: { load: { sealedDirs: [sealedDir] } } }).success,
      ).toBe(false);
    }

    const sealedDir = path.resolve("vendor-skills");
    const result = OpenClawSchema.safeParse({
      skills: { load: { sealedDirs: [`  ${sealedDir}  `] } },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.skills?.load?.sealedDirs).toEqual([sealedDir]);
    }
  });
});
