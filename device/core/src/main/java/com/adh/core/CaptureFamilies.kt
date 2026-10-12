package com.adh.core

/**
 * Which crypto hook families the agent installs for ONE scoped package.
 *
 * This is install-time policy, not a display filter: an unchecked family means those hooks are
 * never installed in that process. That distinction is the point — measured 2026-10-11, a lightly
 * obfuscated target killed itself (SIGSEGV `SI_USER`, i.e. an injected signal) while our GOT hooks
 * were live, so the surface a scoped app gets should be the surface the user actually asked for,
 * not "everything, then filter the records".
 *
 * Default is ALL ON, which is exactly the behaviour before this existed, so an absent entry in the
 * scope file changes nothing and an older reader stays correct.
 */
data class CaptureFamilies(
    val digest: Boolean = true,
    val hmac: Boolean = true,
    val symmetric: Boolean = true,
    val asymmetric: Boolean = true,
    val tls: Boolean = true,
    val aead: Boolean = true,
) {
    val isDefault: Boolean get() = this == DEFAULT

    /**
     * One-line form for the Zygisk companion → target-process hop: the companion socket is
     * line-framed (no embedded newline) and the request budget is small, so the policy crosses as
     * `d=1,h=0,…` rather than as JSON.
     */
    fun toFlagString(): String = buildString {
        append(flag('d', digest)); append(',')
        append(flag('h', hmac)); append(',')
        append(flag('s', symmetric)); append(',')
        append(flag('a', asymmetric)); append(',')
        append(flag('t', tls)); append(',')
        append(flag('e', aead))
    }

    companion object {
        val DEFAULT = CaptureFamilies()

        /**
         * Tolerant parse of [toFlagString]. An absent or unparseable token keeps the DEFAULT (on),
         * so a truncated/older flag line can only ever mean "hook more", never "hook less".
         */
        fun fromFlagString(raw: String): CaptureFamilies {
            if (raw.isBlank()) return DEFAULT
            val seen = HashMap<Char, Boolean>()
            for (token in raw.trim().split(',')) {
                val parts = token.trim().split('=')
                if (parts.size != 2) continue
                val key = parts[0].trim().firstOrNull() ?: continue
                val value = parts[1].trim()
                when (value) {
                    "1" -> seen[key] = true
                    "0" -> seen[key] = false
                }
            }
            fun on(key: Char) = seen[key] ?: true
            return CaptureFamilies(
                digest = on('d'), hmac = on('h'), symmetric = on('s'),
                asymmetric = on('a'), tls = on('t'), aead = on('e'),
            )
        }

        private fun flag(key: Char, on: Boolean) = if (on) "$key=1" else "$key=0"
    }
}
