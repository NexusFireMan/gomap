package com.nexusfireman.gomap

import android.content.Context
import android.net.ConnectivityManager
import java.net.Inet4Address
import java.net.InetAddress

internal fun selectPhoneAddress(addresses: List<InetAddress>): String? = addresses
    .filter { !it.isAnyLocalAddress && !it.isLoopbackAddress && !it.isMulticastAddress && !it.isLinkLocalAddress }
    .sortedBy { if (it is Inet4Address) 0 else 1 }
    .mapNotNull { it.hostAddress }
    .firstOrNull { '%' !in it }

internal fun phoneAddress(context: Context): String? = try {
    val connectivity = context.getSystemService(ConnectivityManager::class.java)
    val network = connectivity?.activeNetwork
    if (network == null) null else selectPhoneAddress(connectivity.getLinkProperties(network)?.linkAddresses.orEmpty().map { it.address })
} catch (_: RuntimeException) { null }
