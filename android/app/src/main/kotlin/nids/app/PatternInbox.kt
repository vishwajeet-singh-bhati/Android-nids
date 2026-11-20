package nids.app
import android.content.Context
import org.json.JSONObject
import org.json.JSONArray

/** Groups related learned flags by socket owner/direction, without inventing attack labels. */
class PatternInbox(private val context: Context){
 private class Window(val attribution: JSONObject){var count=0L;var maximum=Double.NEGATIVE_INFINITY;var cutoff=0.0;var prefix=0;val examples=ArrayList<JSONObject>();val endpoints=LinkedHashSet<String>()}
 private val windows=LinkedHashMap<String,Window>()
 private var lastConfirmed=0L
 @Synchronized fun shortFlow(logit: Double,cutoff: Double,packets: Int,example: String?=null,attribution: JSONObject=JSONObject()){
  val direction=attribution.optString("direction","unknown");val uid=attribution.optInt("uid",-1)
  val peer=attribution.optString("remote_endpoint","unknown").substringBeforeLast(':',"unknown")
  var key="connection|$direction|$uid|"+if(direction=="incoming" || uid<0)peer else "app"
  if(!windows.containsKey(key) && windows.size>=256)key="connection|mixed|overflow"
  val owner=if(key.endsWith("overflow"))JSONObject().put("status","unknown").put("direction","mixed").put("app_label","Multiple or unknown apps") else attribution
  val w=windows.getOrPut(key){Window(JSONObject(owner.toString()))};w.count++;w.maximum=maxOf(w.maximum,logit);w.cutoff=cutoff;w.prefix=maxOf(w.prefix,packets)
  if(example!=null && w.examples.size<3)w.examples.add(JSONObject(example))
  if(w.endpoints.size<8 && attribution.has("remote_endpoint"))w.endpoints.add(attribution.getString("remote_endpoint"))
 }
 @Synchronized fun flush(behavior: JSONObject?,healthy: Boolean,behaviorExample: JSONObject?=null,allowBehavior: Boolean=true): List<JSONObject>{
  val out=ArrayList<JSONObject>()
  if(healthy)for((key,w) in windows){out.add(ObservationStore.record(context,"connection_pattern",w.count,JSONObject().put("fingerprint",key).put("attribution",w.attribution).put("remote_endpoints_sample",JSONArray(w.endpoints.toList())).put("detector","shortflow_cnn_24721").put("max_model_logit",w.maximum).put("threshold_logit",w.cutoff).put("observed_prefix_packets",w.prefix).put("aggregation_seconds",5).put("flags_in_window",w.count).put("training_examples",JSONArray(w.examples)).put("sampling","up to three flagged numeric vectors; endpoint sample capped at eight")))}
  windows.clear()
  val confirmed=behavior?.optLong("confirmed_endpoint_windows") ?: lastConfirmed
  if(healthy && allowBehavior && confirmed>lastConfirmed)out.add(ObservationStore.record(context,"sustained_pattern",confirmed-lastConfirmed,JSONObject().put("fingerprint","sustained|device").put("attribution",JSONObject().put("status","device_level").put("direction","mixed_or_unknown").put("app_label","Multiple or unknown apps")).put("detector","residual_behavior_62657").put("confirmed_endpoint_windows",confirmed-lastConfirmed).put("lookback_seconds",JSONArray(listOf(5,30,60))).put("training_example",behaviorExample)))
  lastConfirmed=confirmed;return out
 }
}
