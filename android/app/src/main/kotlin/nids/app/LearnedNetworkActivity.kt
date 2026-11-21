package nids.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.*
import android.view.View
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LearnedNetworkActivity : Activity() {
 private val bg=Color.rgb(11,18,32);private val surface=Color.rgb(21,34,56)
 private val ink=Color.rgb(237,244,250);private val muted=Color.rgb(169,189,209)
 private val accent=Color.rgb(94,224,186);private val amber=Color.rgb(255,202,122)
 private val ui=Handler(Looper.getMainLooper())
 private lateinit var body: LinearLayout
 private val dynamic=HashMap<String,TextView>()
 private var activityFilter="active";private var historyPage=0
 private var tab=0;private var selectedId="";private var signature="";private var draftNote=""
 private var local: LocalExplainer?=null
 private var notice="";private var alive=true
 private val tick=object: Runnable{override fun run(){refresh();ui.postDelayed(this,3000)}}
 private fun dp(n: Int)=(n*resources.displayMetrics.density).toInt()
 private fun shape(color: Int,radius: Int=18)=GradientDrawable().apply{setColor(color);cornerRadius=dp(radius).toFloat()}
 private fun text(value: String,size: Float=15f,color: Int=ink,bold: Boolean=false)=TextView(this).apply{text=value;textSize=size;setTextColor(color);if(bold)typeface=Typeface.create("sans-serif-medium",Typeface.NORMAL);setPadding(0,dp(4),0,dp(4))}
 private fun column()=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
 private fun card(parent: LinearLayout=body): LinearLayout=column().apply{background=shape(surface);setPadding(dp(18),dp(14),dp(18),dp(14));parent.addView(this,LinearLayout.LayoutParams(-1,-2).apply{bottomMargin=dp(12)})}
 private fun button(parent: LinearLayout,label: String,primary: Boolean=false,action: ()->Unit): Button=Button(this).apply{
  text=label;isAllCaps=false;textSize=15f;setTextColor(if(primary)bg else ink);background=shape(if(primary)accent else Color.rgb(34,51,75),13);minHeight=dp(50);setPadding(dp(10),dp(5),dp(10),dp(5));parent.addView(this,LinearLayout.LayoutParams(-1,dp(52)).apply{topMargin=dp(8)});setOnClickListener{action()}
 }
 private fun bind(parent: LinearLayout,key: String,value: String,size: Float=15f,color: Int=ink){val v=text(value,size,color);dynamic[key]=v;parent.addView(v)}
 private fun stamp(ms: Long)=SimpleDateFormat("dd MMM, HH:mm:ss",Locale.getDefault()).format(Date(ms))
 private fun reviewed(row: JSONObject)=row.optJSONObject("feedback")?.optInt("revision")==row.optInt("revision")
 private fun configureTrace(source: Intent){
  if(source.hasExtra("validation_trace"))getSharedPreferences("background_monitor",MODE_PRIVATE).edit()
   .putBoolean("validation_trace",source.getBooleanExtra("validation_trace",false)).apply()
 }
 override fun onCreate(state: Bundle?){
  super.onCreate(state);window.statusBarColor=bg;window.navigationBarColor=bg
  configureTrace(intent)
  if(intent.getBooleanExtra("start_monitor",false) || getSharedPreferences("background_monitor",MODE_PRIVATE).getBoolean("enabled",false)){if(!LearnedLive.running)startForegroundService(Intent(this,TsanetCaptureService::class.java))}
  selectedId=intent.getStringExtra("observation_id") ?: "";if(selectedId.isNotEmpty())tab=1
  if(android.os.Build.VERSION.SDK_INT>=33)requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS),1)
  val root=column().apply{setBackgroundColor(bg);fitsSystemWindows=true;setPadding(dp(18),dp(12),dp(18),dp(8))}
  root.addView(text("NIDS",30f,ink,true));root.addView(text("LOCAL NETWORK ASSISTANT  ·  MENTOR PREVIEW",10f,accent,true))
  body=column().apply{setPadding(0,dp(16),0,dp(12))}
  root.addView(ScrollView(this).apply{isFillViewport=true;addView(body)},LinearLayout.LayoutParams(-1,0,1f))
  val nav=LinearLayout(this)
  listOf("Monitor","Activity","Device").forEachIndexed{i,label ->
   val b=Button(this).apply{text=label;isAllCaps=false;textSize=14f;setTextColor(ink);background=shape(surface,12);setOnClickListener{tab=i;selectedId="";draftNote="";build()}}
   nav.addView(b,LinearLayout.LayoutParams(0,dp(50),1f).apply{if(i>0)leftMargin=dp(8)})
  };root.addView(nav);setContentView(root)
  Thread{ObservationStore.migrate(applicationContext);ui.post{if(alive)build()}}.start();build()
 }
 private fun build(){
  if(!::body.isInitialized)return
  body.removeAllViews();dynamic.clear()
  when(tab){0->monitorPage();1->if(selectedId.isEmpty())activityPage() else detailPage();else->devicePage()}
  body.addView(text("Built with Llama · runs on this phone",12f,muted))
  if(notice.isNotEmpty())body.addView(text(notice,13f,amber))
  signature=ObservationStore.list(this).toString();refresh()
 }
 private fun monitorPage(){
  val status=card();bind(status,"state","Monitoring",23f,accent);bind(status,"health","Checking capture status",13f,muted)
  val toggle=button(status,"Start monitoring",true){
   if(LearnedLive.running)startService(Intent(this,TsanetCaptureService::class.java).setAction(TsanetCaptureService.STOP))
   else if(Live.running){notice="Pause the reference monitor in Research tools first.";build()}
   else{notice="";startForegroundService(Intent(this,TsanetCaptureService::class.java))}
  };dynamic["toggle"]=toggle
  val metrics=card();bind(metrics,"traffic","0 packets observed",21f);bind(metrics,"checks","0 learned checks",15f,muted);bind(metrics,"reviews","0 observations to review",15f,amber)
  val flow=card();flow.addView(text("How it works",18f,ink,true));flow.addView(text("Traffic summaries → local models → explain → your feedback",15f,accent));flow.addView(text("Connections and recent connection history are checked locally. Monitoring continues in the background; related flags receive an automatic local explanation.",14f,muted));flow.addView(text("A flag is a reason to review activity. It does not confirm an attack or identify the app responsible.",14f,muted))
  val latest=ObservationStore.list(this,filter="active").lastOrNull()
  val recent=card();recent.addView(text("Latest observation",18f,ink,true))
  if(latest==null)recent.addView(text("No observations recorded yet. Monitoring can stay quiet during ordinary activity.",14f,muted))
  else{recent.addView(text(latest.optString("title"),16f));recent.addView(text("${stamp(latest.optLong("time_ms"))} · unconfirmed",12f,amber));button(recent,"Review activity"){tab=1;selectedId=latest.getString("id");build()}}
 }
 private fun activityPage(){
  body.addView(text("Activity",25f,ink,true));body.addView(text("Automatic explanations · seven-day local history",14f,muted))
  val filters=LinearLayout(this)
  for((label,value) in listOf("Active" to "active","Last 7 days" to "all","Dismissed" to "dismissed")){
   val b=Button(this).apply{text=label;isAllCaps=false;textSize=12f;setTextColor(if(activityFilter==value)bg else ink);background=shape(if(activityFilter==value)accent else surface,12);setOnClickListener{activityFilter=value;historyPage=0;build()}}
   filters.addView(b,LinearLayout.LayoutParams(0,dp(46),1f).apply{rightMargin=dp(4)})
  };body.addView(filters)
  val rows=ObservationStore.list(this,50,activityFilter,historyPage*50);val total=ObservationStore.count(this,activityFilter)
  body.addView(text("$total activities · page ${historyPage+1}",12f,muted))
  if(rows.isEmpty()){val empty=card();empty.addView(text("No activity in this view",20f));empty.addView(text("New flags appear automatically. Dismissed items remain in the seven-day history.",14f,muted))}
  for(row in rows.asReversed()){
   val c=card();val dismissed=row.optString("disposition")=="dismissed"
   val local=row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL
   c.addView(text(if(local)"On-device connection · outside network assessment" else if(dismissed)"Dismissed · reported expected by you" else "Unconfirmed · "+row.optString("explanation_status","queued"),12f,if(dismissed || local)muted else amber,true))
   c.addView(text(row.optString("title"),19f,ink,true));c.addView(text(HybridActivityNote.appSummary(row),14f,accent))
   c.addView(text("${stamp(row.optLong("time_ms"))} · ${row.optLong("count")} grouped flags",13f,muted))
   if(row.optBoolean("historical"))c.addView(text("Previous recording",12f,muted))
   button(c,"Open activity"){selectedId=row.getString("id");draftNote="";build()}
  }
  if((historyPage+1)*50<total)button(body,"Older activity"){historyPage++;build()}
  if(historyPage>0)button(body,"Newer activity"){historyPage--;build()}
 }
 private fun detailPage(){
  val row=ObservationStore.get(this,selectedId)
  if(row==null){selectedId="";activityPage();return}
  button(body,"← Activity"){selectedId="";draftNote="";build()}
  val c=card();c.addView(text(if(row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL)"ON-DEVICE CONNECTION · NOT ASSESSED" else "UNCONFIRMED ACTIVITY",11f,amber,true));c.addView(text(row.optString("title"),23f,ink,true));c.addView(text(stamp(row.optLong("time_ms")),12f,muted))
  val owner=row.optJSONObject("attribution") ?: JSONObject()
  bind(c,"appSummary",HybridActivityNote.appSummary(row),17f,accent)
  bind(c,"direction","Direction: "+owner.optString("direction","unknown")+" · "+owner.optString("transport","network traffic"),13f,muted)
  bind(c,"ownership",owner.optString("ownership_note","No reliable app link was recorded for this connection."),12f,muted)
  c.addView(text(row.optString("observation"),14f));bind(c,"incidentCount","${row.optLong("count")} grouped flags · attack type not established",13f,muted)
  val peers=row.optJSONObject("model_evidence")?.optJSONArray("remote_endpoints_sample")
  if(peers!=null && peers.length()>0)c.addView(text("Remote connection sample: "+(0 until peers.length()).take(4).joinToString(", "){peers.optString(it)},12f,muted))
  val explain=card();explain.addView(text("Activity details and guidance",19f,ink,true));explain.addView(text("Recorded facts first · Llama adds local guidance",12f,accent))
  bind(explain,"generatedText",HybridActivityNote.display(row),15f)
  bind(explain,"llama","",13f,amber)
  val feedback=card();feedback.addView(text("Was this expected?",19f,ink,true));feedback.addView(text("Dismiss it if you recognise the activity. Your report is saved locally; it is not verified ground truth.",13f,muted))
  val note=EditText(this).apply{hint="Optional note";setHintTextColor(muted);setTextColor(ink);textSize=14f;maxLines=3;setText(draftNote)};feedback.addView(note)
  for((label,value) in listOf("Expected activity · dismiss" to "expected","Looks suspicious" to "suspicious","Not sure" to "unsure"))button(feedback,label){
   draftNote=note.text.toString()
   try{
    val current=ObservationStore.get(this,row.getString("id")) ?: error("Activity expired")
    ObservationStore.feedback(this,row.getString("id"),row.getInt("revision"),value,draftNote)
    getSystemService(android.app.NotificationManager::class.java).cancel(current.getString("id").hashCode())
    if(value=="expected")AutomaticExplanations.dismiss(this,current.getString("id")) else AutomaticExplanations.pump(applicationContext)
    notice=if(value=="expected")"Dismissed. It remains in your seven-day history." else "Feedback saved. Review the precaution steps below."
    draftNote="";build()
   }catch(e: Exception){Toast.makeText(this,e.message,Toast.LENGTH_LONG).show()}
  }
  if(row.optString("disposition")!="dismissed"){
   val steps=card();steps.addView(text("Next precautions",19f,ink,true));steps.addView(text(row.optString("safe_verification"),14f))
   val packages=owner.optJSONArray("packages")
   if(owner.optString("status")=="best_effort" && packages?.length()==1)button(steps,"Review this app in Settings"){startActivity(Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,android.net.Uri.parse("package:"+packages.optString(0))))}
   button(steps,"Review network settings"){startActivity(Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS))}
  }else body.addView(text("Dismissed by you. Detection remains active; future unrelated activity is still checked.",13f,muted))
 }
 private fun devicePage(){
  body.addView(text("On this device",25f,ink,true))
  val stats=card();stats.addView(text("Live resource use",18f,ink,true));bind(stats,"ram","Measuring app RAM…",21f);bind(stats,"cpu","",14f,muted);bind(stats,"battery","",14f,muted);bind(stats,"temperature","",14f,muted);stats.addView(text("RAM includes Llama while it is active. CPU is for the monitoring process. Battery readings cover the whole phone, including the screen and other apps.",12f,muted))
  val health=card();health.addView(text("Monitoring health",18f,ink,true));bind(health,"queue","",14f);bind(health,"coverage","",13f,muted);health.addView(text("Skipped data is reported as limited coverage. Kernel-level packet loss is not measured.",12f,muted))
  val scope=card();scope.addView(text("Network coverage",18f,ink,true))
  scope.addView(text("Alerts assess connections with other devices. Connections that stay inside this phone are counted separately; they are not labelled safe.",14f,muted))
  bind(scope,"localTraffic","",13f,muted)
  val prefs=getSharedPreferences("background_monitor",MODE_PRIVATE)
  scope.addView(Switch(this).apply{
   text="Alert on on-device connections (experimental)";setTextColor(ink);textSize=14f
   isChecked=prefs.getBoolean("include_device_local_alerts",false)
   setOnCheckedChangeListener{_,enabled->
    prefs.edit().putBoolean("include_device_local_alerts",enabled).apply()
    if(!enabled){
     val ids=ObservationStore.reclassifyDeviceLocal(this@LearnedNetworkActivity)
     val manager=getSystemService(android.app.NotificationManager::class.java)
     ids.forEach{manager.cancel(it.hashCode())}
     if(LlamaLive.observationId in ids)LlamaClient.cancel()
    }
    notice=if(enabled)"Experimental on-device alerts enabled. False alarms are possible." else "On-device connections are counted separately. Their saved history is retained."
    build()
   }
  })
  val llama=card();llama.addView(text("Local explanation model",18f,ink,true));llama.addView(text("Llama 3.2 1B Instruct\nSpinQuant INT4 EO8 · ExecuTorch\nAutomatic explanations; warm cache for about 2 min idle\nWeights: approximately 1.06 GiB",14f,accent));bind(llama,"llama","Ready on device",13f,muted)
  val measurements=try{JSONObject(assets.open("tsanet_phone_benchmarks.json").bufferedReader().use{it.readText()})}catch(_: Exception){null}
  if(measurements!=null){val measured=card();measured.addView(text("Measured on this Pixel",18f,ink,true));measured.addView(text(measurements.optString("display_summary"),14f,muted))}
  val privacy=card();privacy.addView(text("Local by design",18f,ink,true));privacy.addView(text("No cloud inference. The app has no internet permission. Feedback and observations stay on this phone unless you export them.",14f,muted));button(privacy,"Export progress and feedback"){startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").putExtra(Intent.EXTRA_TITLE,"nids-progress.json"),42)}
  val about=card();about.addView(text("About this preview",18f,ink,true));about.addView(text("Version "+packageManager.getPackageInfo(packageName,0).versionName,12f,accent));about.addView(text("A local network monitor using connection statistics and recent history. Attack categories are estimates; phone detection and false-alarm coverage are still being evaluated.",13f,muted));button(about,"Research tools"){startActivity(Intent(this,MainActivity::class.java).putExtra("research",true))}
 }
 private fun refresh(){
  if(!::body.isInitialized)return
  val rows=ObservationStore.list(this);val version=rows.toString()
  if(tab!=2 && selectedId.isEmpty() && signature!=version){signature=version;build();return}
  val b=try{JSONObject(LearnedLive.behaviorSnapshot)}catch(_: Exception){JSONObject()}
  dynamic["state"]?.text=if(LearnedLive.running)LearnedLive.status else "Monitoring paused"
  dynamic["health"]?.text=if(LearnedLive.running)LearnedLive.quality else "Start when you want to observe network activity."
  dynamic["toggle"]?.text=if(LearnedLive.running)"Pause monitoring" else "Start monitoring"
  dynamic["traffic"]?.text="%,d packets observed".format(LearnedLive.packets)
  dynamic["checks"]?.text="%,d learned checks · %.0f min running".format(LearnedLive.inferences+b.optLong("snapshots"),LearnedLive.seconds/60)
  dynamic["reviews"]?.text="${ObservationStore.count(this,"active")} active activities · ${ObservationStore.queuedCount(this)} explanations pending"
  val resource=try{JSONObject(ResourceMonitor.latest)}catch(_: Exception){JSONObject()}
  if(resource.has("app_pss_kib"))dynamic["ram"]?.text="%.1f MiB app RAM (all processes)".format(resource.optDouble("combined_app_pss_kib",resource.optDouble("app_pss_kib"))/1024)
  dynamic["cpu"]?.text=if(resource.has("app_cpu_one_core_percent"))"Main CPU: %.1f%% of one core · sampled every 5 s".format(resource.optDouble("app_cpu_one_core_percent")) else "CPU: measuring…"
  dynamic["battery"]?.text="Battery: ${resource.optInt("battery_percent",-1)}% · ${if(resource.optInt("plugged")>0)"charging" else "on battery"}"
  dynamic["temperature"]?.text="Battery temperature: %.1f °C".format(resource.optDouble("battery_temperature_c"))
  dynamic["queue"]?.text="Queued: ${LearnedLive.queueDepth} / 4096 · skipped: ${LearnedLive.queueDrops}"
  dynamic["coverage"]?.text=LearnedLive.quality
  dynamic["localTraffic"]?.text="${LearnedLive.localOnlyFlows} on-device connection summaries this session"+
   LearnedLive.lastLocalConnection.takeIf{it.isNotEmpty()}?.let{"\nLatest: $it"}.orEmpty()
  val selected=selectedId.takeIf{it.isNotEmpty()}?.let{ObservationStore.get(this,it)}
  dynamic["incidentCount"]?.text="${selected?.optLong("count") ?: 0} grouped flags · attack type not established"
  if(selected!=null){
   dynamic["generatedText"]?.text=HybridActivityNote.display(selected)
   dynamic["appSummary"]?.text=HybridActivityNote.appSummary(selected)
   val latestOwner=selected.optJSONObject("attribution") ?: JSONObject()
   dynamic["direction"]?.text="Direction: "+latestOwner.optString("direction","unknown")+" · "+latestOwner.optString("transport","network traffic")
   dynamic["ownership"]?.text=latestOwner.optString("ownership_note","No reliable app link was recorded for this connection.")
  }
  dynamic["llama"]?.text=if(LlamaLive.running && (selectedId.isEmpty() || selectedId==LlamaLive.observationId))"${LlamaLive.stage} · ${(android.os.SystemClock.elapsedRealtime()-LlamaLive.startedMs)/1000}s"
   else if(selected!=null)when(selected.optString("explanation_status")){
    "queued"->"Recorded facts shown; local guidance queued"
    "running"->"Recorded facts shown; Llama is writing guidance"
    "complete"->if(selected.optJSONObject("explanation")?.optBoolean("generated_text_accepted")==true)"Recorded facts with guidance from Llama" else "Recorded facts and checked default guidance"
    "skipped"->"Dismissed · automatic explanation stopped"
    "cancelled"->"Explanation cancelled; evidence remains in the log"
    "failed"->"Recorded facts remain available; Llama guidance unavailable"
    "not_applicable"->"On-device connection · retained outside network assessment"
    else->"Previously recorded activity"
   }else if(LlamaLive.workerResident)"Warm model ready · releases after about 2 min idle" else "Loads automatically when activity is flagged"
 }
 @Deprecated("Activity result API")
 override fun onActivityResult(requestCode: Int,resultCode: Int,data: Intent?){
  super.onActivityResult(requestCode,resultCode,data)
  if(requestCode!=42 || resultCode!=RESULT_OK)return
  val uri=data?.data ?: return
  Thread{
   try{
    val resources=JSONArray();File(filesDir,"resources_v1.jsonl").takeIf{it.exists()}?.readLines()?.takeLast(240)?.forEach{try{resources.put(JSONObject(it))}catch(_: Exception){}}
    val report=JSONObject().put("schema",2).put("app_version",packageManager.getPackageInfo(packageName,0).versionName).put("device",android.os.Build.MODEL).put("android",android.os.Build.VERSION.RELEASE).put("exported_ms",System.currentTimeMillis()).put("retention_days",7).put("resource_samples",resources).put("feedback_is_verified_truth",false).put("automatic_retraining",false).put("llama","Llama 3.2 1B SpinQuant INT4 EO8 via ExecuTorch")
    contentResolver.openOutputStream(uri)!!.use{ObservationStore.export(this,it,report)}
    ui.post{if(alive){notice="Progress and feedback exported.";build()}}
   }catch(e: Exception){ui.post{if(alive){notice="Export failed: ${e.message}";build()}}}
  }.start()
 }
 override fun onNewIntent(next: Intent){super.onNewIntent(next);setIntent(next);configureTrace(next);if(next.getBooleanExtra("start_monitor",false) && !LearnedLive.running)startForegroundService(Intent(this,TsanetCaptureService::class.java));selectedId=next.getStringExtra("observation_id") ?: "";tab=if(selectedId.isNotEmpty())1 else 0;build()}
 override fun onResume(){super.onResume();ResourceMonitor.acquire(this,"screen");ui.post(tick)}
 override fun onPause(){ui.removeCallbacks(tick);ResourceMonitor.release("screen");super.onPause()}
 override fun onDestroy(){alive=false;local?.stop();super.onDestroy()}
 @Deprecated("Activity back API")
 override fun onBackPressed(){if(selectedId.isNotEmpty()){selectedId="";draftNote="";build()}else if(tab!=0){tab=0;build()}else super.onBackPressed()}
}
