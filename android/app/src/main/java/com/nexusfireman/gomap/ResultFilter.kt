package com.nexusfireman.gomap

internal fun visiblePortResults(rows: List<Observation>, onlyOpen: Boolean): List<Observation> =
    rows.filter { it.state == "open" || (!onlyOpen && it.state == "filtered") }
