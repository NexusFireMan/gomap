package com.nexusfireman.gomap

enum class PortPreset {
    CUSTOM, COMMON, ALL;
    fun specification(manual: String): String = when (this) {
        CUSTOM -> manual.trim()
        COMMON -> "@common1000"
        ALL -> "1-65535"
    }
}
