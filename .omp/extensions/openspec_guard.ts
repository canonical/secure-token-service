/**
 * OMP Tool-Loop Extension (`c8`) for Secure Token Service OpenSpec Verification.
 *
 * Hooks into `tool_result` and `session_stop` so any write/edit touching `openspec/`
 * automatically reminds and gates the agent on `python3 scripts/validate_openspec.py`
 * and `python3 scripts/check_openspec_drift.py`.
 */

import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

export default function openspecGuardExtension(pi: ExtensionAPI): void {
	pi.setLabel("OpenSpec Guard");
	let dirtyOpenSpec = false;

	pi.on("tool_result", async event => {
		const toolName = String(event.toolName || "").toLowerCase();
		const input = (event.input ?? {}) as Record<string, unknown>;
		const targetPath = String(input.path ?? input.filePath ?? input.input ?? "");

		if ((toolName === "write" || toolName === "edit" || toolName === "ast_edit") && targetPath.includes("openspec/")) {
			dirtyOpenSpec = true;
			return {
				additionalContext:
					"[openspec_guard] OpenSpec artifact modified. Run `python3 scripts/validate_openspec.py` and `python3 scripts/check_openspec_drift.py` before finishing.",
			};
		}

		if (toolName === "bash") {
			const cmd = String(input.command ?? "");
			if (cmd.includes("validate_openspec.py") && !event.isError) {
				dirtyOpenSpec = false;
			}
		}
	});

	pi.on("session_stop", async event => {
		if (!dirtyOpenSpec || event.stop_hook_active) return;
		return {
			decision: "block",
			reason:
				"OpenSpec files were modified in this session without passing verification. Run `python3 scripts/validate_openspec.py` and `python3 scripts/check_openspec_drift.py` and resolve all findings before concluding.",
		};
	});
}
