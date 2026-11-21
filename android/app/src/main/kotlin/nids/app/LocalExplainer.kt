package nids.app
import android.content.Context
import android.os.SystemClock
import org.json.JSONObject
import org.pytorch.executorch.extension.llm.*
import java.io.File

private object WarmLlamaModel {
 var module: LlmModule?=null
 var signature=""
 fun acquire(context: Context): Triple<LlmModule,Long,Long>{
  val directory=File(context.filesDir,"llama");val model=File(directory,"Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte");val tokenizer=File(directory,"tokenizer.model")
  require(model.exists() && tokenizer.exists()){"Local Llama files are missing"}
  val current="${model.length()}:${model.lastModified()}:${tokenizer.length()}:${tokenizer.lastModified()}"
  if(module!=null && signature==current)return Triple(module!!,0L,0L)
  LlamaLive.stage="Checking local INT4 model";val verifyStart=SystemClock.elapsedRealtime()
  require(LearnedShortFlowScorer.sha256(model)=="8715cdba9e91f6bede00cc5f2d6b12397b95225da5630c4972a8da03001cda3b"){"Llama checksum failed"}
  require(LearnedShortFlowScorer.sha256(tokenizer)=="82e9d31979e92ab929cd544440f129d9ecd797b69e327f80f17e1c50d5551b55"){"Tokenizer checksum failed"}
  val verify=SystemClock.elapsedRealtime()-verifyStart;LlamaLive.stage="Loading local INT4 model";val loadStart=SystemClock.elapsedRealtime()
  module?.close();module=null
  val loaded=LlmModule(LlmModuleConfig.create().modulePath(model.absolutePath).tokenizerPath(tokenizer.absolutePath).temperature(0f).loadMode(LlmModuleConfig.LOAD_MODE_MMAP).build())
  try{loaded.load()}catch(e: Throwable){loaded.close();throw e}
  module=loaded;signature=current
  return Triple(loaded,verify,SystemClock.elapsedRealtime()-loadStart)
 }
}
class LocalExplainer(private val context: Context){
 @Volatile private var active: LlmModule?=null
 @Volatile private var cancelled=false
 fun stop(){cancelled=true;active?.stop()}
 fun explain(evidence: JSONObject): JSONObject{
  android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND)
  val totalStart=SystemClock.elapsedRealtime();LlamaLive.running=true;LlamaLive.startedMs=totalStart;ResourceMonitor.acquire(context,"llama")
  try{
   val (module,verifyMs,loadMs)=WarmLlamaModel.acquire(context);active=module
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
   val instructions=if(tsanetFacts!=null)"Write ONE short sentence, 8 to 20 words. Rephrase the supplied manual phone check. Keep its meaning. Add no facts, commands, headings or introduction."
       else if(cascadeFacts!=null)"Explain these detector facts in three plain-language sentences, at most 65 words. Describe the suspected pattern and a relevant measured fact. Identify only the supplied socket owner, or say ownership is unknown. Incoming apps receive traffic. Say this does not confirm an attack. The category is a model hypothesis; never invent payload contents, causes, apps or attack types. Suggest one manual app or network check. No commands or automatic actions."
       else "Explain these detector facts in three plain-language sentences, at most 55 words. Say this does not confirm an attack. App means socket owner, not necessarily the initiator; incoming apps receive traffic. Never invent apps, attack types or causes. Recommend checking expected use, app permissions or network settings. No commands or automatic actions."
   val userContent=if(tsanetFacts!=null)"Manual check to restate: ${HybridActivityNote.guidance(tsanetFacts)}" else safe.toString()
   val prompt="<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n$instructions<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n$userContent<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
   val raw=StringBuilder();var stats="";val error=java.util.concurrent.atomic.AtomicReference("");var firstCallback=0L
   val tokenBudget=if(tsanetFacts!=null)48 else if(cascadeFacts!=null)96 else 80
   val boundedCallback=BoundedLlmCallback(tokenBudget,{module.stop()},object: LlmCallback{
    override fun onResult(value: String){if(firstCallback==0L)firstCallback=SystemClock.elapsedRealtime()-totalStart;raw.append(value)}
    override fun onStats(value: String){stats=value.take(12000)}
    override fun onError(code: Int,message: String){error.set("$code: $message")}
   })
   val handler=android.os.Handler(android.os.Looper.getMainLooper());val timeout=Runnable{error.set("Local generation timed out");module.stop()}
   LlamaLive.stage="Writing explanation";val generateStart=SystemClock.elapsedRealtime();handler.postDelayed(timeout,90000)
   try{module.generate(prompt,LlmGenerationConfig.create().echo(false).seqLen(if(tsanetFacts!=null)512 else if(structuredFacts!=null)1024 else 512).maxNewTokens(tokenBudget).temperature(0f).build(),boundedCallback)}finally{handler.removeCallbacks(timeout)}
   val generationMs=SystemClock.elapsedRealtime()-generateStart
   val stoppedAtBudget=boundedCallback.limitReached;val tokenCallbacks=boundedCallback.tokenCallbacks
   if(cancelled)error.set("Explanation cancelled")
   val rawText=raw.toString().replace(Regex("<\\|[^>]+\\|>"),"").trim()
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
   val accepted=if(tsanetFacts!=null)error.get().isEmpty() && !stoppedAtBudget && HybridActivityNote.guidanceAccepted(text,tsanetFacts)
       else error.get().isEmpty() && !stoppedAtBudget && text.split(Regex("\\s+")).size in 8..(if(cascadeFacts!=null)65 else 90) && uncertainty && !prohibited && attributionConsistent && !Regex("\\d+%|\\b\\d{1,3}(\\.\\d{1,3}){3}\\b").containsMatchIn(text)
   val fallback=if(tsanetFacts!=null)TsanetExplanationFacts.fallback(tsanetFacts) else if(cascadeFacts!=null)CascadeExplanationFacts.fallback(cascadeFacts) else "The model flagged an unusual connection pattern; this does not confirm an attack. Check whether the activity was expected, then review the associated app when available and your network in Android Settings."
   val display=if(tsanetFacts!=null)HybridActivityNote.render(tsanetFacts,if(accepted)text else HybridActivityNote.guidance(tsanetFacts)) else if(accepted)text else fallback
   return JSONObject().put("display",display).put("generated_text_accepted",accepted).put("display_source",if(tsanetFacts!=null && accepted)"verified_facts_local_llama_guidance" else if(tsanetFacts!=null)"verified_facts_default_guidance" else if(accepted)"local_llama" else "evidence_based_fallback").put("pipeline_version",if(tsanetFacts!=null)HybridActivityNote.VERSION else "legacy").put("token_budget",tokenBudget).put("stream_token_callbacks",tokenCallbacks).put("generation_stopped_at_budget",stoppedAtBudget).put("guidance_only_generation",tsanetFacts!=null).put("guidance_text",if(tsanetFacts!=null && accepted)text else if(tsanetFacts!=null)HybridActivityNote.guidance(tsanetFacts) else "").put("factual_prefix",if(tsanetFacts!=null)HybridActivityNote.prefix(tsanetFacts) else "").put("raw_local_draft",rawText).put("normalized_local_draft",text).put("runtime_error",error.get()).put("elapsed_ms",SystemClock.elapsedRealtime()-totalStart).put("total_including_verification_ms",SystemClock.elapsedRealtime()-totalStart).put("verification_ms",verifyMs).put("load_ms",loadMs).put("generation_ms",generationMs).put("warm_model_reused",loadMs==0L).put("quantization","SpinQuant INT4 EO8").put("model","Llama 3.2 1B Instruct").put("first_callback_including_verification_ms",firstCallback).put("output_characters",display.length).put("runtime_stats_raw",stats).put("evidence_revision_used",current.optInt("revision",evidence.optInt("revision"))).put("scope","verified detector facts plus optional local guidance; no confirmed attack or causal app attribution")
  }finally{active=null;LlamaLive.running=false;LlamaLive.stage="Warm local model ready";ResourceMonitor.captureNow(context);ResourceMonitor.release("llama")}
 }
}
