---
title: "Seal vendor skills at startup"
sidebarTitle: "Sealed vendor skills"
summary: "Provision immutable Linux skill trees into encrypted SQLite storage, verify startup sealing, replace generations, and recover safely."
read_when:
  - Provisioning vendor skills in an immutable Linux appliance
  - Updating or recovering skills.load.sealedDirs
  - Troubleshooting sealed skill startup, access, or decryption failures
---

Sealed vendor skills let a Linux Gateway load appliance-provided skills without
leaving their plaintext source tree on disk after startup. OpenClaw encrypts a
validated generation into the shared state database, verifies it, removes the
source skill directories, and continues serving their original logical paths to
supported host embedded agents.

<Warning>
  Sealing is destructive. OpenClaw does not provide an unseal or plaintext
  export command. Keep the authoritative vendor source outside the Gateway host
  or in your appliance build and provisioning system.
</Warning>

This feature is for casual plaintext-at-rest deterrence on managed appliances.
It is not a security boundary against the host operator, root, a compromised
Gateway process, or a model that has already received the skill content.

## Before you begin

Prepare all of the following before enabling `skills.load.sealedDirs`:

| Requirement                                       | Why it matters                                                                                      |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Linux systemd host with a valid `/etc/machine-id` | The machine identity participates in generation key derivation.                                     |
| Dedicated absolute root                           | Relative paths, `~`, filesystem roots, overlapping roots, and state-directory overlap are rejected. |
| Complete vendor source bundle                     | Every non-empty source tree is treated as the complete replacement generation.                      |
| Gateway ownership and permissions                 | The Gateway user must read every source and remove each discovered skill directory.                 |
| External source backup                            | The shared database cannot recreate a deleted plaintext source tree.                                |
| Planned Gateway restart                           | Sealed roots are captured only at startup; config changes are restart-required.                     |

Do not place `SKILL.md` directly in the configured root. Put each skill in its
own directory. Grouping directories are supported up to the discovery depth
limit:

```text
/opt/vendor/openclaw-skills/
  policy-pack/
    SKILL.md
    references/
      controls.md
  support/
    incident-runbook/
      SKILL.md
      templates/
        response.md
```

The configured root may contain unrelated files and grouping directories.
OpenClaw removes only directories identified as skills in the committed
manifest.

## Validate the source tree

OpenClaw fails closed before deleting source when validation fails. The
configured root, grouping directories, skill directories, and files must be
owned by root or by the Gateway user and must not be group- or world-writable.

Inside discovered skill trees, OpenClaw rejects:

- symlinks;
- hard-linked files;
- executable files;
- sockets, devices, and other non-regular files;
- `.git` and `node_modules` directories;
- individual files larger than 16 MiB;
- a root exceeding 200 skills, 2,000 directories, 4,000 files, or 128 MiB;
- skills discovered deeper than six grouping-directory levels.

Inspect a staged source before startup:

```bash
namei -l /opt/vendor/openclaw-skills
find /opt/vendor/openclaw-skills -type l -print
find /opt/vendor/openclaw-skills -type f -links +1 -print
find /opt/vendor/openclaw-skills -type f -perm /111 -print
find /opt/vendor/openclaw-skills -perm /022 -print
```

The `find` commands should print nothing. Review `namei -l` and confirm each
path component has the intended owner and mode. Run these checks as part of
appliance image construction, not as a replacement for OpenClaw validation.

## Configure sealed roots

Add one or more absolute roots to `~/.openclaw/openclaw.json`:

```json5
{
  skills: {
    load: {
      sealedDirs: ["/opt/vendor/openclaw-skills"],
    },
  },
}
```

Configured roots must not overlap each other. They also must not contain or sit
inside the OpenClaw state directory, including through a symlinked ancestor.
The canonical encrypted store is `state/openclaw.sqlite` under the active
OpenClaw state directory.

Use [agent skill allowlists](/tools/skills#agent-allowlists) when only selected
agents should see a sealed skill. Under `tools.fs.workspaceOnly`, file tools may
read only sealed skill subtrees present in the run's resolved skill snapshot.
Tool policies can remove sealed file access by denying `group:fs` or individual
file tools.

## Seal the first generation

Restart the Gateway only after the complete source bundle is in place:

```bash
openclaw gateway restart
openclaw gateway status --deep
```

For every configured root, startup performs one ordered workflow:

1. Discover skill directories and validate the complete source tree.
2. Read each regular file through no-follow, bounded file operations.
3. Encrypt the manifest and every file with AES-256-GCM.
4. Commit the generation and its blobs to `state/openclaw.sqlite`.
5. Read, authenticate, decrypt, and verify the committed generation.
6. Remove only the skill directories recorded in that manifest.
7. Mark source cleanup complete and expose the in-process sealed runtime index.

OpenClaw does not delete plaintext until the database transaction commits and
the committed generation passes verification. If the process stops between
commit and cleanup, the next startup resumes deletion from that exact manifest
instead of capturing the partial tree left on disk.

## Verify the result

Confirm the Gateway is healthy and the skill metadata is available:

```bash
openclaw gateway status --deep
openclaw skills info policy-pack --json
test ! -e /opt/vendor/openclaw-skills/policy-pack/SKILL.md
```

The final command exits successfully only when the plaintext `SKILL.md` is no
longer present. The configured root and unrelated grouping content may remain.

Test content access through a host embedded agent. The agent may use `read`,
`ls`, `find`, and `grep` against the original absolute skill path, or invoke an
eligible skill with `/skill:<name>`. Do not use shell commands as the access
test; no plaintext filesystem projection exists.

## Understand the access boundary

| Surface                                     | Metadata                           | Decrypted content                                                             |
| ------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------- |
| Host embedded agent with an eligible skill  | Yes                                | Read-only through OpenClaw `read`, `ls`, `find`, `grep`, and skill invocation |
| `openclaw skills list`, `info`, and `check` | Yes                                | No unseal or plaintext export                                                 |
| Host shell and external processes           | No virtual view                    | No                                                                            |
| Sandboxed agents                            | Sealed skills omitted              | No                                                                            |
| Native CLI and ACP backends                 | Sealed skills omitted from prompts | No                                                                            |

The `coding` tool profile includes sealed discovery tools when a sealed runtime
is active. `group:fs` allow and deny rules apply to `read`, `ls`, `find`,
`grep`, `write`, `edit`, and `apply_patch`. Sealed paths remain read-only even
when normal host filesystem writes are permitted.

OpenClaw marks decrypted `read` and `grep` results so diagnostic cache traces
and trajectory exports replace their bodies with a redaction notice. This does
not make derived text confidential: model responses, summaries, normal session
context, and user-requested quotations can still contain skill material.

## Replace a generation

Treat replacement as a complete bundle operation. OpenClaw cannot know which
skills your vendor intended to include, so any valid non-empty source tree at a
completed sealed root becomes the next complete generation.

Use this update sequence:

1. Stop the Gateway so it cannot start against a partially provisioned tree.
2. Provision every skill directory for the replacement bundle at the same
   configured absolute root.
3. Re-run the source validation checks above.
4. Start or restart the Gateway.
5. Verify Gateway health, skill metadata, and plaintext removal.

```bash
openclaw gateway stop
# Provision the complete replacement bundle here.
openclaw gateway start
openclaw gateway status --deep
```

Do not copy replacement directories gradually while an automatic service
restart can occur. A partial but otherwise valid tree can become the active
generation and omit skills that were present previously.

## Back up and restore

The encryption key is derived with HKDF-SHA256 from the systemd machine ID and
a random per-generation salt. AES-GCM authenticated data also binds each blob
to its root identity, generation, and object identity.

For a same-host state restore, preserve the original `/etc/machine-id` and the
OpenClaw state database together. A changed machine ID, OS reinstall, moved
configured root, or cross-host restore cannot load the old generation through
the new configuration.

Use one of these recovery paths:

- Restore the original machine identity together with the matching state.
- Reprovision the complete vendor source at the same configured root and start
  the Gateway to create a new generation for the current machine identity.

Reprovisioning can replace an undecryptable generation only after the previous
generation's source cleanup completed. If cleanup was interrupted, restore the
matching machine identity first so OpenClaw can verify the committed manifest
and safely finish deletion.

## Disable a sealed root

Remove the path from `skills.load.sealedDirs` and restart the Gateway. OpenClaw
stops loading that root, but it does not recreate plaintext and does not delete
the encrypted database rows. Keep this behavior in mind when planning data
retention and host decommissioning.

## Troubleshooting

| Symptom                                                                          | Cause and action                                                                                                                                                                |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `skills.load.sealedDirs is supported only on Linux systemd hosts`                | Run the Gateway on Linux with a valid systemd machine ID, or remove the setting.                                                                                                |
| `entries must be absolute paths`                                                 | Replace relative or `~` paths with canonical absolute paths.                                                                                                                    |
| Root overlaps the OpenClaw state directory                                       | Move the vendor root outside the active state directory and restart.                                                                                                            |
| Ownership, writable-mode, symlink, hard-link, executable, or file-type rejection | Correct the staged source. OpenClaw has not committed or deleted that rejected generation.                                                                                      |
| `Configured sealed skill root has no stored generation`                          | Provision a complete source tree for the first generation, then restart.                                                                                                        |
| `Cannot decrypt sealed skill root`                                               | Restore the matching machine ID and state, or provision a complete replacement tree for the current host.                                                                       |
| Incomplete cleanup reports an uncommitted skill directory                        | Do not let a replacement tree mix with cleanup remnants. Restore the committed generation's machine identity, move unexpected directories aside, and restart to finish cleanup. |
| A host agent cannot read a sealed path                                           | Confirm the skill is eligible for that agent and that tool profile, `group:fs`, and `tools.fs.workspaceOnly` policy permit the requested subtree.                               |
| Shell, sandbox, or native CLI cannot read the path                               | This is expected. Use a host embedded agent or an eligible skill invocation.                                                                                                    |

## Related documentation

- [Skills](/tools/skills) for precedence, eligibility, and agent allowlists.
- [Skills config](/tools/skills-config) for the complete `skills.*` schema.
- [Skills CLI](/cli/skills) for metadata inspection commands.
- [Gateway configuration](/gateway/configuration) for restart behavior.
- [Trajectory export](/tools/trajectory) for diagnostic redaction behavior.
