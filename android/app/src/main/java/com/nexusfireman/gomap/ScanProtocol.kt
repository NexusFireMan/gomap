package com.nexusfireman.gomap

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal val wireJson = Json { ignoreUnknownKeys = true; encodeDefaults = true }

@Serializable
data class Observation(
    val port: Int,
    val state: String,
    val open: Boolean,
    val service: String = "",
    val version: String = "",
    val hostname: String = "",
    val confidence: String = "",
    val evidence: String = "",
    @SerialName("latency_ms") val latencyMs: Long = 0,
)

@Serializable
data class CoverageSummary(
    val requested: Int,
    val completed: Int,
    val open: Int,
    val closed: Int,
    val filtered: Int,
    val unknown: Int,
    val unreported: Int,
    val cancelled: Boolean,
    @SerialName("duration_ms") val durationMs: Long,
)

@Serializable
private data class WireEvent(
    @SerialName("schema_version") val schemaVersion: Int,
    val type: String,
    val host: String,
    val result: Observation? = null,
    val summary: CoverageSummary? = null,
    val error: String = "",
)

internal fun parseObservation(text: String): Observation {
    val event = wireJson.decodeFromString<WireEvent>(text)
    require(event.schemaVersion == 1 && event.type == "result" && event.host.isNotBlank()) { "Unsupported native event" }
    val row = requireNotNull(event.result) { "Missing native observation" }
    require(row.port in 1..65535 && row.state in setOf("open", "closed", "filtered", "unknown") && row.open == (row.state == "open")) { "Invalid native observation" }
    return row
}

internal fun parseSummary(text: String, delivered: Collection<Observation>): Pair<CoverageSummary, String> {
    val event = wireJson.decodeFromString<WireEvent>(text)
    require(event.schemaVersion == 1 && event.type == "summary") { "Missing native summary" }
    val s = requireNotNull(event.summary)
    require(listOf(s.requested, s.completed, s.open, s.closed, s.filtered, s.unknown, s.unreported).all { it in 0..4096 } &&
        s.completed == delivered.size && s.requested == s.completed + s.unreported &&
        s.completed == s.open + s.closed + s.filtered + s.unknown && s.durationMs >= 0) { "Native coverage does not reconcile" }
    require(s.open == delivered.count { it.state == "open" } && s.closed == delivered.count { it.state == "closed" } &&
        s.filtered == delivered.count { it.state == "filtered" } && s.unknown == delivered.count { it.state == "unknown" }) { "Native states disagree with coverage" }
    return s to event.error
}

@Serializable
private data class ExportReport(
    @SerialName("schema_version") val schemaVersion: Int = 1,
    @SerialName("app_version") val appVersion: String,
    val target: String,
    val ports: String,
    val status: String,
    val results: List<Observation>,
    val coverage: CoverageSummary?,
)

fun ScanState.reportJson(): String = wireJson.encodeToString(ExportReport(
    appVersion = BuildConfig.VERSION_NAME, target = requireNotNull(scannedHost), ports = requireNotNull(scannedPorts),
    status = phase.name.lowercase(), results = observations, coverage = summary,
))
