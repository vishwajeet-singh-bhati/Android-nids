// Test-only copy of the production explainer for matched component A/B experiments.
package nids.app
import android.content.Context
import android.os.SystemClock
import org.json.JSONObject
import org.pytorch.executorch.extension.llm.*
import java.io.File

private object PerformanceWarmLlamaModel {
 var module: LlmModule?=null
 var signature=""
 fun release(){module?.close();module=null;signature=""}
 fun acquire(context: Context,small: Boolean=false): Triple<LlmModule,Long,Long>{
  val directory=File(context.filesDir,if(small)"performance_v1/small_explainer" else "llama")
  val model=File(directory,if(small)"smollm2_135m_xnnpack_8da8w.pte" else "Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte")
  val tokenizer=File(directory,if(small)"tokenizer.json" else "tokenizer.model")
  require(model.exists() && tokenizer.exists()){"Local Llama files are missing"}
  val current="${model.name}:${model.length()}:${model.lastModified()}:${tokenizer.length()}:${tokenizer.lastModified()}"
  if(module!=null && signature==current)return Triple(module!!,0L,0L)
  LlamaLive.stage="Checking local INT4 model";val verifyStart=SystemClock.elapsedRealtime()
  require(LearnedShortFlowScorer.sha256(model)==if(small)"9eac1f8076069fcd7583024d16dc412251d1ce3f13359991229526010a0ce380" else "8715cdba9e91f6bede00cc5f2d6b12397b95225da5630c4972a8da03001cda3b"){"Model checksum failed"}
  require(LearnedShortFlowScorer.sha256(tokenizer)==if(small)"9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c" else "82e9d31979e92ab929cd544440f129d9ecd797b69e327f80f17e1c50d5551b55"){"Tokenizer checksum failed"}
  val verify=SystemClock.elapsedRealtime()-verifyStart;LlamaLive.stage="Loading local INT4 model";val loadStart=SystemClock.elapsedRealtime()
  module?.close();module=null
  val loaded=LlmModule(LlmModuleConfig.create().modulePath(model.absolutePath).tokenizerPath(tokenizer.absolutePath).temperature(0f).loadMode(LlmModuleConfig.LOAD_MODE_MMAP).build())
  try{loaded.load()}catch(e: Throwable){loaded.close();throw e}
  module=loaded;signature=current
  return Triple(loaded,verify,SystemClock.elapsedRealtime()-loadStart)
 }
}
class PerformanceLocalExplainer(private val context: Context){
 companion object{
  fun releaseModel(){PerformanceWarmLlamaModel.release()}
  /** PR17-inspired test only: readiness includes one bounded generation. */
  fun bootWarmup(context: Context): JSONObject {
   val tick=SystemClock.elapsedRealtime();val (module,verify,load)=PerformanceWarmLlamaModel.acquire(context)
   val raw=StringBuilder();var stats="";var failure=""
   module.resetContext()
   val handler=android.os.Handler(android.os.Looper.getMainLooper())
   val timeout=Runnable{failure="Warmup timed out";module.stop()};handler.postDelayed(timeout,30000)
   try{
    module.generate("<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\nReply OK.<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
     LlmGenerationConfig.create().echo(false).seqLen(64).maxNewTokens(1).temperature(0f).build(),object: LlmCallback{
      override fun onResult(value: String){raw.append(value);module.stop()}
      override fun onStats(value: String){stats=value}
      override fun onError(code: Int,message: String){failure="$code: $message"}
     })
   }finally{handler.removeCallbacks(timeout);module.resetContext()}
   check(failure.isEmpty()){failure};val native=JSONObject(stats);check(native.getInt("generated_tokens")==1){stats}
   return JSONObject().put("boot_total_ms",SystemClock.elapsedRealtime()-tick).put("verification_ms",verify)
    .put("load_ms",load).put("warmup_runtime_stats",native).put("discarded_output",raw.toString())
  }
  fun nativeBudgetProbes(context: Context): JSONObject {
   val (module,_,_)=PerformanceWarmLlamaModel.acquire(context);val cases=org.json.JSONArray()
   for(limit in listOf(1,3,48)){
    module.resetContext();val raw=StringBuilder();var stats="";var failure=""
    val bounded=BoundedLlmCallback(limit,{module.stop()},object: LlmCallback{
     override fun onResult(value: String){raw.append(value)}
     override fun onStats(value: String){stats=value}
     override fun onError(code: Int,message: String){failure="$code: $message"}
    })
    val handler=android.os.Handler(android.os.Looper.getMainLooper());val timeout=Runnable{failure="Budget probe timed out";module.stop()}
    handler.postDelayed(timeout,30000)
    try{module.generate("<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\nList the numbers from one through one hundred, separated by commas. No introduction.<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n",
      LlmGenerationConfig.create().echo(false).seqLen(512).maxNewTokens(limit).temperature(0f).build(),bounded)}finally{handler.removeCallbacks(timeout);module.resetContext()}
    check(failure.isEmpty()){failure};val native=JSONObject(stats)
    // Android can emit framing/newline callbacks in addition to generated
    // tokens. The production contract is an upper bound, not an obligation
    // to generate exactly limit tokens; verify canonical native counters.
    check(bounded.limitReached && bounded.tokenCallbacks==limit && native.getInt("generated_tokens") in 1..limit){"limit=$limit callbacks=${bounded.tokenCallbacks} stats=$stats"}
    cases.put(JSONObject().put("limit",limit).put("forwarded_callbacks",bounded.tokenCallbacks).put("received_callbacks",bounded.receivedCallbacks).put("native_generated_tokens",native.getInt("generated_tokens")).put("stopped",bounded.limitReached).put("raw_fixture_output",raw.toString()))
   }
   return JSONObject().put("passed",true).put("cases",cases).put("scope","Actual production callback against native model on numeric generation fixtures, no incident or traffic")
  }
 }
 @Volatile private var active: LlmModule?=null
 @Volatile private var cancelled=false
 fun stop(){cancelled=true;active?.stop()}
 fun explain(evidence: JSONObject,performanceProfile: String="current"): JSONObject{
  require(performanceProfile in setOf("current","concise_prefix96","structured_tail48","guidance_only48","plain_hybrid48","small_full96","small_hybrid48"))
  if(performanceProfile!="current")require(evidence.optBoolean("performance_fixture") && evidence.optString("id").isEmpty())
  android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
  val totalStart=SystemClock.elapsedRealtime();LlamaLive.running=true;LlamaLive.startedMs=totalStart;ResourceMonitor.acquire(context,"llama")
  try{
   val small=performanceProfile.startsWith("small_")
   val (module,verifyMs,loadMs)=PerformanceWarmLlamaModel.acquire(context,small);active=module
   require(!cancelled){"Explanation cancelled"}
   module.resetContext() // Fresh evidence per activity; cached weights are retained, not conversation history.
   val current=evidence.optString("id").takeIf{it.isNotEmpty()}?.let{ObservationStore.get(context,it)} ?: evidence
   val owner=current.optJSONObject("attribution") ?: JSONObject()
   val packages=owner.optJSONArray("packages")
   val app=if(owner.optString("status")=="best_effort" && packages?.length()==1)packages.optString(0).take(100).replace(Regex("[^A-Za-z0-9._]"),"") else "unknown"
   val tsanetFacts=TsanetExplanationFacts.from(current.optJSONObject("model_evidence"))
   val cascadeFacts=CascadeExplanationFacts.from(current.optJSONObject("model_evidence")?.optJSONObject("cascade_evidence"))
   val structuredFacts=tsanetFacts ?: cascadeFacts
   val safe=structuredFacts ?: JSONObject().put("pattern",if(current.optString("kind")=="sustained_pattern")"repeated_traffic_windows" else "unusual_connections").put("app_package",app).put("direction",owner.optString("direction","unknown")).put("flags",current.optLong("count",1)).put("attack_type","not established")
   val instructions=if(tsanetFacts!=null)"Rewrite the supplied observation as a clear notification in three or four short sentences, at most 65 words. Keep the model estimate, packet count, socket owner or unknown ownership, and the manual check. Keep the sentence: This does not confirm an attack. Preserve limited-history information. Add no facts or causes. Do not describe malware, viruses, attackers, payloads, or login failures. No commands or automatic actions."
       else if(cascadeFacts!=null)"Explain these detector facts in three plain-language sentences, at most 65 words. Describe the suspected pattern and a relevant measured fact. Identify only the supplied socket owner, or say ownership is unknown. Incoming apps receive traffic. Say this does not confirm an attack. The category is a model hypothesis; never invent payload contents, causes, apps or attack types. Suggest one manual app or network check. No commands or automatic actions."
       else "Explain these detector facts in three plain-language sentences, at most 55 words. Say this does not confirm an attack. App means socket owner, not necessarily the initiator; incoming apps receive traffic. Never invent apps, attack types or causes. Recommend checking expected use, app permissions or network settings. No commands or automatic actions."
   val plain=performanceProfile in setOf("plain_hybrid48","small_full96","small_hybrid48") && tsanetFacts!=null
   val detachedGuidance=performanceProfile in setOf("guidance_only48","plain_hybrid48","small_hybrid48") && tsanetFacts!=null
   val tail=performanceProfile in setOf("structured_tail48","guidance_only48","plain_hybrid48","small_hybrid48") && tsanetFacts!=null
   val concise=performanceProfile!="current" && tsanetFacts!=null
   val guidance=if(plain)PerformancePlainNote.guidance(tsanetFacts!!) else if(tsanetFacts!=null)TsanetExplanationFacts.guidance(tsanetFacts.optString("suspected_pattern")) else ""
   val selectedInstructions=if(detachedGuidance)"Write ONE short sentence, 8 to 20 words. Rephrase the supplied manual phone check. Keep its meaning. Add no facts, commands, headings or introduction." else if(tail)"Continue the notification with ONE short manual check, 8 to 20 words. Use only the supplied check. Do not repeat the observation. No heading, new facts, causes or commands." else if(concise)"Return only a short notification, at most 55 words. Keep the supplied model hypothesis, packet count, socket owner or unknown ownership, manual check and any incomplete-history warning. No heading, new facts, causes, commands or automatic actions. Continue the supplied opening sentence." else instructions
   val userContent=if(tail)"Manual check to restate: $guidance" else if(plain)PerformancePlainNote.render(tsanetFacts!!) else if(concise)TsanetExplanationFacts.fallback(tsanetFacts!!) else if(tsanetFacts!=null)TsanetExplanationFacts.prompt(tsanetFacts) else safe.toString()
   var assistantPrefix=if(tail && plain)PerformancePlainNote.prefix(tsanetFacts!!) else if(tail)TsanetExplanationFacts.fallback(tsanetFacts!!).removeSuffix(guidance).trim()+" " else if(concise && !small)"This does not confirm an attack. " else ""
   if(tail && !tsanetFacts!!.optBoolean("history_complete") && !assistantPrefix.contains("history",true))assistantPrefix+="Recent connection history is still building. "
   val promptPrefix=if(detachedGuidance)"" else assistantPrefix
   val prompt=if(small)"<|im_start|>system\n$selectedInstructions<|im_end|>\n<|im_start|>user\n$userContent<|im_end|>\n<|im_start|>assistant\n$promptPrefix" else "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n$selectedInstructions<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n$userContent<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n$promptPrefix"
   val raw=StringBuilder();var stats="";val error=java.util.concurrent.atomic.AtomicReference("");var firstCallback=0L
   val handler=android.os.Handler(android.os.Looper.getMainLooper());val timeout=Runnable{error.set("Local generation timed out");module.stop()}
   LlamaLive.stage="Writing explanation";val generateStart=SystemClock.elapsedRealtime();handler.postDelayed(timeout,90000)
   try{module.generate(prompt,LlmGenerationConfig.create().echo(false).seqLen(if(concise)512 else if(structuredFacts!=null)1024 else 512).maxNewTokens(if(tail)48 else if(concise)96 else if(tsanetFacts!=null)128 else if(cascadeFacts!=null)96 else 80).temperature(0f).build(),object: LlmCallback{
    override fun onResult(value: String){if(firstCallback==0L)firstCallback=SystemClock.elapsedRealtime()-totalStart;raw.append(value)}
    override fun onStats(value: String){stats=value.take(12000)}
    override fun onError(code: Int,message: String){error.set("$code: $message")}
   })}finally{handler.removeCallbacks(timeout)}
   val generationMs=SystemClock.elapsedRealtime()-generateStart
   if(cancelled)error.set("Explanation cancelled")
   val completion=if(detachedGuidance)nids.core.ExplanationText.notificationDraft(raw.toString()) else raw.toString()
   val rawText=(assistantPrefix+completion).replace(Regex("<\\|[^>]+\\|>"),"").trim()
   val text=if(tsanetFacts!=null)nids.core.ExplanationText.notificationDraft(rawText) else rawText
   val lower=text.lowercase()
   val uncertainty=listOf("does not confirm","not confirmed","unconfirmed","not proof").any{it in lower}
   val category=tsanetFacts?.optString("suspected_pattern")?.let{when(it){"Brute Force"->"credential_attack";"DDoS"->"ddos";"DoS"->"dos";"Port Scan"->"port_scan";"Bot"->"bot_activity";"Web Attack"->"web_attack";else->""}} ?: cascadeFacts?.optString("suspected_pattern") ?: ""
   val prohibited=listOf("malware","attacker","infected","compromised","ransomware","phishing","exfiltrat","sudo","iptables","rm -","adb ").any{it in lower} ||
       (listOf("brute force","bruteforce").any{it in lower} && category!="credential_attack") ||
       ("ddos" in lower && category!="ddos") ||
       (structuredFacts!=null && listOf("port scan","portscan").any{it in lower} && category!="port_scan") ||
       (structuredFacts!=null && "heartbleed" in lower && category!="heartbleed")
   val suppliedApp=safe.optString("app_package","unknown")
   val mentionedPackages=Regex("\\b(?:com|org|net|io|android)(?:\\.[A-Za-z][A-Za-z0-9_]*)+\\b").findAll(text).map{it.value}.toList()
   val attributionConsistent=if(tsanetFacts!=null)TsanetExplanationFacts.draftConsistent(text,tsanetFacts) else cascadeFacts==null ||
       (mentionedPackages.all{it==suppliedApp} &&
        (if(suppliedApp=="unknown")listOf("unknown","could not","cannot").any{it in lower} else suppliedApp.lowercase() in lower) &&
        (cascadeFacts.optString("socket_role")!="receiver" || "receiv" in lower))
   val suffix=completion.replace(Regex("<\\|[^>]+\\|>"),"").trim()
   val tailValid=!tail || (suffix.split(Regex("\\s+")).size in 6..25 && Regex("\\b(check|review|verify|consider|look|see)\\b",RegexOption.IGNORE_CASE).containsMatchIn(suffix) &&
       !Regex("\\b(attack|malicious|caused|because|proof|definitely|certainly|hack)\\b",RegexOption.IGNORE_CASE).containsMatchIn(suffix))
   val accepted=error.get().isEmpty() && text.split(Regex("\\s+")).size in 8..(if(tsanetFacts!=null)75 else if(cascadeFacts!=null)65 else 90) && uncertainty && !prohibited && attributionConsistent && tailValid && !Regex("\\d+%|\\b\\d{1,3}(\\.\\d{1,3}){3}\\b").containsMatchIn(text)
   val fallback=if(plain)PerformancePlainNote.render(tsanetFacts!!) else if(tsanetFacts!=null)TsanetExplanationFacts.fallback(tsanetFacts) else if(cascadeFacts!=null)CascadeExplanationFacts.fallback(cascadeFacts) else "The model flagged an unusual connection pattern; this does not confirm an attack. Check whether the activity was expected, then review the associated app when available and your network in Android Settings."
   return JSONObject().put("display",if(accepted)text else fallback).put("generated_text_accepted",accepted).put("display_source",if(accepted && tail)"hybrid_fixed_facts_local_model_guidance" else if(accepted)"local_model" else "evidence_based_fallback").put("raw_local_draft",rawText).put("normalized_local_draft",text).put("runtime_error",error.get()).put("elapsed_ms",SystemClock.elapsedRealtime()-totalStart).put("total_including_verification_ms",SystemClock.elapsedRealtime()-totalStart).put("verification_ms",verifyMs).put("load_ms",loadMs).put("generation_ms",generationMs).put("warm_model_reused",loadMs==0L).put("quantization",if(small)"8da8w" else "SpinQuant INT4 EO8").put("model",if(small)"SmolLM2 135M Instruct" else "Llama 3.2 1B Instruct").put("first_callback_including_verification_ms",firstCallback).put("output_characters",text.length).put("runtime_stats_raw",stats).put("evidence_revision_used",current.optInt("revision",evidence.optInt("revision"))).put("performance_profile",performanceProfile).put("fixed_assistant_prefix",assistantPrefix).put("scope","local explanation of detector evidence; no verified attack attribution")
  }finally{active=null;LlamaLive.running=false;LlamaLive.stage="Warm local model ready";ResourceMonitor.captureNow(context);ResourceMonitor.release("llama")}
 }
}
