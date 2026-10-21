/**
 * OpenCode Tool-Loop Plugin (`c8`) for Secure Token Service OpenSpec Verification.
 *
 * Hooks into `tool.execute.after` and `experimental.chat.system.transform` so any
 * write/edit touching `openspec/` automatically reminds and gates the agent on
 * `python3 scripts/validate_openspec.py` and `python3 scripts/check_openspec_drift.py`.
 */

export const OpenSpecGuardPlugin = async () => {
  let dirtyOpenSpec = false;

  return {
    "tool.execute.after": async (
      input: { tool: string; args?: Record<string, unknown> },
      output: { output?: string }
    ) => {
      const toolName = String(input?.tool || "").toLowerCase();
      const filePath = String(input?.args?.filePath || input?.args?.path || "");
      if (
        (toolName.includes("write") || toolName.includes("edit") || toolName.includes("patch")) &&
        filePath.includes("openspec/")
      ) {
        dirtyOpenSpec = true;
        const notice =
          "\n[openspec_guard] OpenSpec artifact modified. Run `python3 scripts/validate_openspec.py` and `python3 scripts/check_openspec_drift.py` before finishing.";
        if (typeof output?.output === "string") {
          output.output += notice;
        }
      }
      if (toolName.includes("bash") && String(input?.args?.command || "").includes("validate_openspec.py")) {
        dirtyOpenSpec = false;
      }
    },
    "experimental.chat.system.transform": async (
      _input: Record<string, unknown>,
      output: { system: string[] }
    ) => {
      if (dirtyOpenSpec && Array.isArray(output?.system)) {
        output.system.push(
          "REMINDER: OpenSpec files were modified in this session. You MUST run `python3 scripts/validate_openspec.py` and `python3 scripts/check_openspec_drift.py` and resolve all findings before concluding."
        );
      }
    },
  };
};

export default OpenSpecGuardPlugin;
