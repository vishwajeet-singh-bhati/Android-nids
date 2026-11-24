package nids.app

import org.json.JSONObject

/** Bounded, body-free manual results, keyed so an incoming SMS cannot replace a manual check. */
object SafetyResults {
    private val values = LinkedHashMap<String, JSONObject>()
    @Synchronized fun put(id: String, result: JSONObject) {
        values[id] = JSONObject(result.toString())
        while (values.size > 32) values.remove(values.keys.first())
    }
    @Synchronized fun get(id: String): JSONObject? = values[id]?.let { JSONObject(it.toString()) }
    @Synchronized fun clear() = values.clear()
}
