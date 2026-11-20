package nids.core

object AlignedContract{
    const val VERSION="phone-aligned-v2"
    const val FLOW=32
    const val CONTEXT=115
    val WINDOWS=listOf(5,30,300)
    val STATS=listOf("flows","out_packets","in_packets","out_bytes","in_bytes","distinct_peers","distinct_remote_ports","distinct_local_ports",
        "no_peer_packets_fraction","rst_fraction","syn_fraction","tcp_fraction","udp_fraction","observed_auth_failures","http_requests","web_indicators")
    val AUX=listOf("http_requests","http_responses","http_auth_failures","http_4xx","http_5xx","login_like_requests","sql_like_requests","script_like_requests",
        "tls_prefix_seen","cleartext_http_seen","payload_packets","duplicate_payload_fragments","header_buffer_full","payload_gaps_or_truncation","basic_auth_seen","long_header_seen","ssh_banner_seen","ftp_banner_or_credentials_seen")
    val NAMES=WINDOWS.flatMap{w->listOf("source","destination").flatMap{role->STATS.map{"${w}s_${role}_$it"}}}+AUX.map{"flow_$it"}+listOf("history_age_log_seconds_capped_300")
    fun json(value: Any?): String=when(value){null->"null";is String->"\""+value.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n")+"\""
        is Number,is Boolean->value.toString();is Map<*,*>->value.entries.joinToString(",","{","}"){json(it.key.toString())+":"+json(it.value)}
        is Iterable<*>->value.joinToString(",","[","]"){json(it)};else->json(value.toString())}
    fun specification()=mapOf("version" to VERSION,"flow_dimension" to FLOW,"context_dimension" to CONTEXT,"context_names" to NAMES,
        "windows_seconds" to WINDOWS,"history" to "strictly prior completed decisions; all observed traffic incident to watched endpoint only",
        "flags" to "actual per-packet counts; retransmissions retained","timestamps" to "capture seconds, 50ms bounded reorder, deterministic integer-second idle ticks; no minute rounding",
        "flow_boundaries" to "RST; both FIN plus 1s quiet; 30s max/TCP idle; 10s UDP idle",
        "zero_duration" to "retained, duration and undefined rates encoded 0","ip_prefix_bytes" to AlignedPacketParser.IP_PREFIX,
        "payload_prefix_bytes" to 512,"cleartext_scope" to "first bounded HTTP header block in each direction, numeric observations only; body lines ignored and TLS never decrypted",
        "normalization" to "train-only log1p of flow and flow auxiliary; standardization with floor std .05")
}
