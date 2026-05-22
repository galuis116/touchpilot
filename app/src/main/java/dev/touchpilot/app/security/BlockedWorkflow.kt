package dev.touchpilot.app.security

/**
 * Workflow-level blocklist matcher used by [DefaultActionPolicy].
 *
 * Each matcher decides whether a [ToolPolicyRequest] should be hard-blocked
 * because the **user intent** corresponds to one of TouchPilot's refused
 * workflows (payments, password entry, destructive settings changes, etc.).
 *
 * The previous implementation in [DefaultActionPolicy] used a single
 * pre-built haystack that concatenated the tool name, the argument values,
 * **and the entire `activeScreen` accessibility-tree snapshot**, then ran
 * substring matching against that haystack. That had a long-tail false-
 * positive problem: whenever the foreground app happened to display any of
 * the blocked keywords (e.g. "bank" on a banking app home screen,
 * "Password" on Settings -> Passwords & accounts, "purchase" in a help
 * article), every medium- and high-risk tool was hard-blocked regardless
 * of what the user was actually trying to do.
 *
 * Each [BlockedWorkflow] now exposes its own [matches] method that receives
 * the full request and decides which subset of the request to inspect.
 * Only the explicit intent surface — the tool name and its arguments — is
 * inspected; the arbitrary text of the foreground app is no longer included.
 *
 * The targeted screen-aware checks that *are* legitimate — refusing
 * `type_text` when the typed value itself looks sensitive
 * ([DefaultActionPolicy.isSensitiveTextEntry]) and escalating
 * `tap "Send"` in a messaging app to approval
 * ([DefaultActionPolicy.isMessageSend]) — remain in place and continue to
 * consult `activeScreen` directly. They are surgical and tied to a specific
 * tool/action combination, unlike the previous broad substring scan.
 */
sealed class BlockedWorkflow {

    /** Human-readable reason used in both audit log entries and user messages. */
    abstract val reason: String

    /** Returns true when this matcher considers [request] to fall under its workflow. */
    abstract fun matches(request: ToolPolicyRequest): Boolean

    /**
     * Matches when the user-intent surface of the request (the tool name and
     * its argument values, joined by spaces, lowercased) contains the matcher's
     * needle.
     *
     * The intent surface is what the local router / local model / MCP source
     * explicitly chose to do. The active-screen accessibility tree is
     * deliberately excluded so that unrelated app content cannot cause a
     * benign action to be hard-blocked.
     */
    data class IntentKeyword(
        val needle: String,
        override val reason: String
    ) : BlockedWorkflow() {
        override fun matches(request: ToolPolicyRequest): Boolean {
            val intentSurface = buildIntentSurface(request)
            return needle in intentSurface
        }

        private fun buildIntentSurface(request: ToolPolicyRequest): String {
            return buildString {
                append(request.tool.name)
                append(' ')
                append(request.args.values.joinToString(separator = " "))
            }.lowercase()
        }
    }

    companion object {
        /**
         * The default blocklist mirrors the original keywords from
         * `DefaultActionPolicy.blockedWorkflow` and from
         * [dev.touchpilot.app.agent.IntentGate.UnsafePatterns], so that the
         * gate's early refusal at the user-task layer and the policy's
         * refusal at the tool-execution layer continue to agree on which
         * workflows are off-limits.
         *
         * Order matters only for the "first match wins" semantics in
         * [DefaultActionPolicy]; more specific phrases are listed before
         * shorter substrings of themselves to keep the reason strings
         * informative.
         */
        val DefaultWorkflows: List<BlockedWorkflow> = listOf(
            IntentKeyword("payment", "payments are blocked"),
            IntentKeyword("pay ", "payments are blocked"),
            IntentKeyword("password", "password workflows are blocked"),
            IntentKeyword("passcode", "password workflows are blocked"),
            IntentKeyword("account recovery", "account recovery workflows are blocked"),
            IntentKeyword("recover account", "account recovery workflows are blocked"),
            IntentKeyword("factory reset", "destructive settings changes are blocked"),
            IntentKeyword("erase all", "destructive settings changes are blocked"),
            IntentKeyword("delete account", "destructive account changes are blocked"),
            IntentKeyword("purchase", "purchases are blocked"),
            IntentKeyword("buy now", "purchases are blocked"),
            IntentKeyword("bank", "banking or financial actions are blocked"),
            IntentKeyword("wire transfer", "banking or financial actions are blocked"),
            IntentKeyword("transfer money", "banking or financial actions are blocked")
        )
    }
}
