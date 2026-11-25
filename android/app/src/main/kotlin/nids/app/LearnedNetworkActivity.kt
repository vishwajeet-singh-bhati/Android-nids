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
import nids.authentication.AuthenticationEpisodePolicy
import android.view.View
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class LearnedNetworkActivity : Activity() {
 private val bg=Color.rgb(246,247,249);private val surface=Color.WHITE
 private val ink=Color.rgb(27,32,38);private val muted=Color.rgb(86,96,108)
 private val accent=Color.rgb(31,82,136);private val amber=Color.rgb(139,77,15)
 private val ui=Handler(Looper.getMainLooper())
 private lateinit var body: LinearLayout
 private val dynamic=HashMap<String,TextView>()
 private val navigationButtons=ArrayList<Button>()
 private var activityFilter="active";private var historyPage=0
 private var checkRequestId="";private var sharedInput="";private var advancedExpanded=false;private var tab=0;private var selectedId="";private var signature="";private var draftNote=""
 private var local: LocalExplainer?=null
 private var notice="";private var alive=true
 private val tick=object: Runnable{override fun run(){refresh();ui.postDelayed(this,3000)}}
 private fun dp(n: Int)=(n*resources.displayMetrics.density).toInt()
 private fun shape(color: Int,radius: Int=8)=GradientDrawable().apply{setColor(color);cornerRadius=dp(radius).toFloat()}
 private fun text(value: String,size: Float=15f,color: Int=ink,bold: Boolean=false)=TextView(this).apply{text=value;textSize=size;setTextColor(color);if(bold)typeface=Typeface.create("sans-serif-medium",Typeface.NORMAL);setPadding(0,dp(4),0,dp(4))}
 private fun column()=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL}
 private fun card(parent: LinearLayout=body): LinearLayout=column().apply{background=shape(surface);setPadding(dp(18),dp(14),dp(18),dp(14));parent.addView(this,LinearLayout.LayoutParams(-1,-2).apply{bottomMargin=dp(12)})}
 private fun button(parent: LinearLayout,label: String,primary: Boolean=false,action: ()->Unit): Button=Button(this).apply{
  text=label;isAllCaps=false;textSize=15f;setTextColor(if(primary)Color.WHITE else ink);background=shape(if(primary)accent else Color.rgb(231,235,240),13);minHeight=dp(50);setPadding(dp(10),dp(5),dp(10),dp(5));parent.addView(this,LinearLayout.LayoutParams(-1,-2).apply{topMargin=dp(8)});setOnClickListener{action()}
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
  window.decorView.systemUiVisibility=View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
  configureTrace(intent)
  if(intent.action==Intent.ACTION_SEND){acceptSharedText(intent);tab=1}
  if(intent.getBooleanExtra("start_monitor",false) || getSharedPreferences("background_monitor",MODE_PRIVATE).getBoolean("enabled",false)){if(!LearnedLive.running)startForegroundService(Intent(this,TsanetCaptureService::class.java))}
  selectedId=intent.getStringExtra("observation_id") ?: "";if(selectedId.isNotEmpty())tab=2
  if(android.os.Build.VERSION.SDK_INT>=33)requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS),1)
  val root=column().apply{setBackgroundColor(bg);fitsSystemWindows=true;setPadding(dp(18),dp(12),dp(18),dp(8))}
  val brand=LinearLayout(this).apply{gravity=android.view.Gravity.CENTER_VERTICAL}
  brand.addView(ImageView(this).apply{setImageResource(R.drawable.rakshak_logo);contentDescription="Rakshak logo";scaleType=ImageView.ScaleType.FIT_CENTER},LinearLayout.LayoutParams(dp(44),dp(44)).apply{rightMargin=dp(10)})
  brand.addView(text("Rakshak",26f,ink,true));root.addView(brand)
  body=column().apply{setPadding(0,dp(16),0,dp(12))}
  root.addView(ScrollView(this).apply{isFillViewport=true;addView(body)},LinearLayout.LayoutParams(-1,0,1f))
  val nav=LinearLayout(this)
  listOf("Home","Check","Activity","Settings").forEachIndexed{i,label ->
   val b=Button(this).apply{text=label;isAllCaps=false;textSize=14f;setTextColor(ink);background=shape(surface,12);setOnClickListener{tab=i;selectedId="";draftNote="";build()}}
   navigationButtons.add(b)
   nav.addView(b,LinearLayout.LayoutParams(0,dp(50),1f).apply{if(i>0)leftMargin=dp(8)})
  };root.addView(nav);setContentView(root)
  Thread{ObservationStore.migrate(applicationContext);ui.post{if(alive){
   build()
   ObservationStore.list(applicationContext).filter{NetworkObservationPolicy.rejectedIncomingEvidence(it.optJSONObject("model_evidence") ?: JSONObject())}
    .forEach{ObservationNotifications.show(applicationContext,it)}
  }}}.start();build()
 }
 private fun build(){
  if(!::body.isInitialized)return
  navigationButtons.forEachIndexed{i,button->button.setTextColor(if(i==tab)Color.WHITE else muted);button.background=shape(if(i==tab)accent else surface,6)}
  body.removeAllViews();dynamic.clear()
  when(tab){0->monitorPage();1->checkPage();2->if(selectedId.isEmpty())activityPage() else detailPage();else->devicePage()}

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
  val metrics=card();bind(metrics,"reviews","No activity to review",18f,ink)
  val protection=card();protection.addView(text("Messages and links",18f,ink,true))
  bind(protection,"protection","",14f,muted)
  button(protection,"Check a message or link"){tab=1;build()}
  val latest=ObservationStore.list(this,filter="active").lastOrNull()
  val recent=card();recent.addView(text("Latest observation",18f,ink,true))
  if(latest==null)recent.addView(text("No observations recorded yet. Monitoring can stay quiet during ordinary activity.",14f,muted))
  else{recent.addView(text(activityTitle(latest),16f));recent.addView(text("${stamp(latest.optLong("time_ms"))} · unconfirmed",12f,amber));button(recent,"Review activity"){tab=2;selectedId=latest.getString("id");build()}}
 }
 private fun activityPage(){
  body.addView(text("Activity",25f,ink,true));body.addView(text("Saved on this phone for seven days",14f,muted))
  button(body,"Clear history"){confirmClearHistory()}
  val filters=LinearLayout(this)
  for((label,value) in listOf("Active" to "active","Last 7 days" to "all","Dismissed" to "dismissed")){
   val b=Button(this).apply{text=label;isAllCaps=false;textSize=12f;setTextColor(if(activityFilter==value)Color.WHITE else ink);background=shape(if(activityFilter==value)accent else surface,12);setOnClickListener{activityFilter=value;historyPage=0;build()}}
   filters.addView(b,LinearLayout.LayoutParams(0,dp(46),1f).apply{rightMargin=dp(4)})
  };body.addView(filters)
  val rows=ObservationStore.list(this,50,activityFilter,historyPage*50);val total=ObservationStore.count(this,activityFilter)
  body.addView(text("$total activities · page ${historyPage+1}",12f,muted))
  if(rows.isEmpty()){val empty=card();empty.addView(text("No activity in this view",20f));empty.addView(text("New flags appear automatically. Dismissed items remain in the seven-day history.",14f,muted))}
  for(row in rows.asReversed()){
   val c=card();val dismissed=row.optString("disposition")=="dismissed"
   val local=row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL
   c.addView(text(if(local)"On-device connection · outside network assessment" else if(dismissed)"Dismissed · reported expected by you" else "Needs review",12f,if(dismissed || local)muted else amber,true))
   c.addView(text(activityTitle(row),19f,ink,true));c.addView(text(HybridActivityNote.appSummary(row),14f,accent))
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
  val c=card();c.addView(text(activityTitle(row),23f,ink,true));c.addView(text(stamp(row.optLong("time_ms")),13f,muted))
  val owner=row.optJSONObject("attribution") ?: JSONObject()
  val explain=card()
  bind(explain,"generatedText",HybridActivityNote.display(row),17f)
  bind(explain,"llama","",13f,muted)
  val safety=SafetyNote.from(row.optJSONObject("model_evidence"))
  if(safety!=null){
   val technical=TextView(this).apply{text=SafetyNote.details(safety);textSize=13f;setTextColor(muted);visibility=View.GONE}
   button(body,"Technical details"){technical.visibility=if(technical.visibility==View.GONE)View.VISIBLE else View.GONE}
   body.addView(technical)
  }
  val facts=TsanetExplanationFacts.from(row.optJSONObject("model_evidence"))
  if(facts!=null){
   val technical=TextView(this).apply{text=HybridActivityNote.details(facts);textSize=13f;setTextColor(muted);visibility=View.GONE}
   button(body,"Technical details"){technical.visibility=if(technical.visibility==View.GONE)View.VISIBLE else View.GONE}
   body.addView(technical)
  }
  fun submitFeedback(value: String, note: String){
   draftNote=note
   try{
    val id=row.getString("id")
    ObservationStore.feedback(this,id,row.getInt("revision"),value,draftNote)
    currentFocus?.let{focus->
     getSystemService(android.view.inputmethod.InputMethodManager::class.java)
      .hideSoftInputFromWindow(focus.windowToken,0)
    }
    notice=when(value){
     "expected" -> ""
     "unsure" -> if(row.optString("disposition")=="dismissed")"Dismissal undone." else "Feedback saved."
     else -> "Feedback saved. Review the precaution steps below."
    }
    draftNote="";build()
    if(value=="expected")AutomaticExplanations.dismiss(this,id)
    else{
     getSystemService(android.app.NotificationManager::class.java).cancel(id.hashCode())
     AutomaticExplanations.pump(applicationContext)
    }
   }catch(e: Exception){Toast.makeText(this,e.message,Toast.LENGTH_LONG).show()}
  }
  val feedback=card()
  val mutedRepeat=row.optJSONObject("feedback")?.optBoolean("mute_matching_repeats")==true
  if(row.optString("disposition")=="dismissed"){
   feedback.addView(text("Marked as expected",19f,ink,true))
   val status=if(mutedRepeat)"Matching attempts are muted for up to seven days."
    else "This activity is dismissed and stays in your history."
   feedback.addView(text(status,13f,muted))
   button(feedback,if(mutedRepeat)"Undo repeat mute" else "Undo dismissal"){submitFeedback("unsure","")}
  }else{
   feedback.addView(text("Was this expected?",19f,ink,true))
   val eligible=row.optString("kind")=="tsanet_pattern" &&
    row.optJSONObject("model_evidence")?.let(NetworkObservationPolicy::expectedRepeatKey)!=null
   val description=if(eligible)"If you recognize this connection, marking it expected mutes closely matching repeats for up to seven days."
    else "If you recognize this activity, you can dismiss it. Your feedback stays on this phone."
   feedback.addView(text(description,13f,muted))
   val note=EditText(this).apply{hint="Optional note";setHintTextColor(muted);setTextColor(ink);textSize=14f;maxLines=3;setText(draftNote)}
   feedback.addView(note)
   button(feedback,"I expected this"){submitFeedback("expected",note.text.toString())}
   button(feedback,"Looks suspicious"){submitFeedback("suspicious",note.text.toString())}
   button(feedback,"Not sure"){submitFeedback("unsure",note.text.toString())}
  }
  if(row.optString("disposition")!="dismissed"){
   if(safety==null){
   val steps=card();steps.addView(text("Open settings",19f,ink,true))
   val packages=owner.optJSONArray("packages")
   if(owner.optString("status")=="best_effort" && packages?.length()==1)button(steps,"Review this app in Settings"){startActivity(Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,android.net.Uri.parse("package:"+packages.optString(0))))}
   if(safety==null)button(steps,"Review network settings"){startActivity(Intent(android.provider.Settings.ACTION_WIRELESS_SETTINGS))}
   }
  }
 }
 private fun activityTitle(row: JSONObject): String {
  return HybridActivityNote.activityTitle(row)
 }
 private fun confirmClearHistory(){
  AlertDialog.Builder(this).setTitle("Clear activity history?")
   .setMessage("Remove all saved activities, feedback and their notifications from this phone?")
   .setNegativeButton("Cancel",null)
   .setPositiveButton("Clear history"){_,_->
    try{
     val ids=ObservationStore.clearHistory(this)
     val manager=getSystemService(android.app.NotificationManager::class.java)
     ids.forEach{manager.cancel(it.hashCode())}
     if(LlamaLive.observationId in ids)LlamaClient.cancel("History cleared")
     LlamaClient.releaseIfIdle()
     selectedId="";checkRequestId="";historyPage=0;draftNote="";notice="History cleared.";build()
    }catch(e: Exception){Toast.makeText(this,"Could not clear history. Please try again.",Toast.LENGTH_LONG).show()}
   }.show()
 }
 private fun checkPage(){
  body.addView(text("Check a message or link",24f,ink,true))
  body.addView(text("Paste text here, or share it to Rakshak from another app. Links are checked without opening them.",14f,muted))
  val choices=RadioGroup(this).apply{orientation=RadioGroup.HORIZONTAL}
  val message=RadioButton(this).apply{id=View.generateViewId();text="Message";setTextColor(ink)}
  val link=RadioButton(this).apply{id=View.generateViewId();text="Link";setTextColor(ink)}
  choices.addView(message);choices.addView(link);choices.check(if(checkIsLink)link.id else message.id)
  choices.setOnCheckedChangeListener{_,id->checkIsLink=id==link.id}
  body.addView(choices)
  val input=EditText(this).apply{
   hint="Paste message text or a link";setHintTextColor(muted);setTextColor(ink);textSize=16f
   minLines=4;maxLines=8;gravity=android.view.Gravity.TOP;isSaveEnabled=false
   inputType=android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE
   imeOptions=android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
   filters=arrayOf(android.text.InputFilter.LengthFilter(32768));setText(sharedInput)
   addTextChangedListener(object: android.text.TextWatcher {
    override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
    override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { sharedInput=s?.toString().orEmpty() }
    override fun afterTextChanged(s: android.text.Editable?) {}
   })
  }
  body.addView(input)
  button(body,"Check on this phone",true){
   if(input.text.isBlank()){Toast.makeText(this,"Paste a message or link first.",Toast.LENGTH_SHORT).show();return@button}
   val domain=if(choices.checkedRadioButtonId==link.id)"url" else "message"
   checkRequestId=SafetyAnalysisService.submit(this,input.text.toString(),domain)
   input.text.clear();(getSystemService(INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager).hideSoftInputFromWindow(input.windowToken,0)
   refresh()
  }
  val result=card();bind(result,"checkResult","Results will appear here.",16f)
 }
 private fun protectionSettings(){
  val controls=card();controls.addView(text("Detection controls",20f,ink,true))
  controls.addView(text("Each detector can be enabled separately for testing.",14f,muted))
  controls.addView(Switch(this).apply{
   text="Network intrusion monitoring";setTextColor(ink);isChecked=getSharedPreferences("background_monitor",MODE_PRIVATE).getBoolean("enabled",false)
   setOnCheckedChangeListener{_,enabled->
    if(enabled)startForegroundService(Intent(this@LearnedNetworkActivity,TsanetCaptureService::class.java))
    else startService(Intent(this@LearnedNetworkActivity,TsanetCaptureService::class.java).setAction(TsanetCaptureService.STOP))
   }
  })
  controls.addView(text("New SMS messages are checked automatically when enabled below. Links inside them go to the phishing detector; risky links produce a warning. No copy and paste is needed. This does not read WhatsApp or other chat apps.",13f,muted))
  for((label,key) in listOf("SMS scam detector" to SafetyControls.SMS,"Phishing link detector" to SafetyControls.URL)){
   controls.addView(Switch(this).apply{text=label;setTextColor(ink);isChecked=SafetyControls.enabled(this@LearnedNetworkActivity,key)
    setOnCheckedChangeListener{_,enabled->SafetyControls.set(this@LearnedNetworkActivity,key,enabled)}
   })
  }
  controls.addView(Switch(this).apply{
   text="Automatically check incoming SMS and links";setTextColor(ink)
   isChecked=SafetyControls.enabled(this@LearnedNetworkActivity,SafetyControls.INCOMING) &&
    checkSelfPermission(Manifest.permission.RECEIVE_SMS)==android.content.pm.PackageManager.PERMISSION_GRANTED
   setOnCheckedChangeListener{_,enabled->
    if(enabled && checkSelfPermission(Manifest.permission.RECEIVE_SMS)!=android.content.pm.PackageManager.PERMISSION_GRANTED){
     isChecked=false;requestPermissions(arrayOf(Manifest.permission.RECEIVE_SMS),43)
    }else SafetyControls.set(this@LearnedNetworkActivity,SafetyControls.INCOMING,enabled)
   }
  })
  controls.addView(text("Incoming SMS uses the enabled detectors and needs your permission. Pasted messages and shared links can be checked separately. Turning a detector off leaves that part unchecked.",13f,muted))
 }
 override fun onRequestPermissionsResult(code: Int,permissions: Array<out String>,results: IntArray){
  super.onRequestPermissionsResult(code,permissions,results)
  if(code==43){
   val granted=results.firstOrNull()==android.content.pm.PackageManager.PERMISSION_GRANTED
   SafetyControls.set(this,SafetyControls.INCOMING,granted)
   notice=if(granted)"Incoming SMS checks enabled." else "SMS permission was not granted. You can still paste a message to check it."
   build()
  }
 }
 private fun devicePage(){
  body.addView(text("Settings",25f,ink,true))
  protectionSettings()
  val privacy=card();privacy.addView(text("Private by default",19f,ink,true))
  privacy.addView(text("Checks and explanations run on this phone. Message text is processed without saving it. Saved warnings are kept for seven days.",15f,muted))
  val model=card();model.addView(text("About Rakshak",19f,ink,true))
  model.addView(text("Rakshak checks network activity, SMS messages and links. Llama helps explain the alerts in everyday language.",15f,muted))
  model.addView(text("Version "+packageManager.getPackageInfo(packageName,0).versionName,13f,muted))
  button(body,"Clear activity history"){confirmClearHistory()}
  button(body,if(advancedExpanded)"Hide advanced settings" else "Advanced settings"){advancedExpanded=!advancedExpanded;build()}
  if(advancedExpanded)advancedPage()
 }
 private fun advancedPage(){
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
  scope.addView(Switch(this).apply{
   text="SSH and FTP episode alerts (experimental)";setTextColor(ink);textSize=14f
   isChecked=prefs.getBoolean(AuthenticationEpisodePolicy.PREF,false)
   setOnCheckedChangeListener{_,enabled->prefs.edit().putBoolean(AuthenticationEpisodePolicy.PREF,enabled).apply()}
  })
  scope.addView(text("Groups repeated incoming SSH or FTP connections from the same device. This can quiet isolated connections and delay a warning until more connections are observed.",13f,muted))
  val llama=card();llama.addView(text("Local explanation model",18f,ink,true));llama.addView(text("Llama 3.2 1B Instruct\nSpinQuant INT4 EO8 · ExecuTorch\nAutomatic explanations; warm cache for about 2 min idle\nWeights: approximately 1.06 GiB",14f,accent));bind(llama,"llama","Ready on device",13f,muted)
  val measurements=try{JSONObject(assets.open("tsanet_phone_benchmarks.json").bufferedReader().use{it.readText()})}catch(_: Exception){null}
  if(measurements!=null){val measured=card();measured.addView(text("Measured on this Pixel",18f,ink,true));measured.addView(text(measurements.optString("display_summary"),14f,muted))}
  val privacy=card();privacy.addView(text("Local by design",18f,ink,true));privacy.addView(text("No cloud inference. The app has no internet permission. Feedback and observations stay on this phone unless you export them.",14f,muted));button(privacy,"Export progress and feedback"){startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/json").putExtra(Intent.EXTRA_TITLE,"nids-progress.json"),42)}
  val about=card();about.addView(text("About this preview",18f,ink,true));about.addView(text("Version "+packageManager.getPackageInfo(packageName,0).versionName,12f,accent));about.addView(text("A local network monitor using connection statistics and recent history. Attack categories are estimates; phone detection and false-alarm coverage are still being evaluated.",13f,muted));button(about,"Research tools"){startActivity(Intent(this,MainActivity::class.java).putExtra("research",true))}
 }
 private fun refresh(){
  if(!::body.isInitialized)return
  dynamic["protection"]?.text="SMS detector "+(if(SafetyControls.enabled(this,SafetyControls.SMS))"on" else "off")+
   " / Link detector "+(if(SafetyControls.enabled(this,SafetyControls.URL))"on" else "off")+
   "\nIncoming SMS "+(if(SafetyControls.enabled(this,SafetyControls.INCOMING) && checkSelfPermission(Manifest.permission.RECEIVE_SMS)==android.content.pm.PackageManager.PERMISSION_GRANTED)"enabled" else "off")
  if(checkRequestId.isNotEmpty()){
   val result=SafetyResults.get(checkRequestId)
   dynamic["checkResult"]?.text=when{
    result==null->"Checking on this phone..."
    result.optString("analysis_status")=="cancelled"->"Settings changed during the check. Run it again."
    result.optString("analysis_status")=="busy"->"Rakshak is busy. Please try again shortly."
    result.optString("analysis_status")=="unavailable"->"The check could not start. Open Rakshak and try again."
    result.optString("analysis_status")=="disabled"->"The requested detector is turned off. Enable it in Settings to run this check."
    result.optString("risk_level")=="low"->SafetyNote.quietResult(result)
    else->SafetyNote.render(result)
   }
  }
  val rows=ObservationStore.list(this);val version=rows.toString()
  if(tab!=3 && tab!=1 && selectedId.isEmpty() && signature!=version){signature=version;build();return}
  val b=try{JSONObject(LearnedLive.behaviorSnapshot)}catch(_: Exception){JSONObject()}
  dynamic["state"]?.text=if(LearnedLive.running)LearnedLive.status else "Monitoring paused"
  dynamic["health"]?.text=if(LearnedLive.running)LearnedLive.quality else "Start when you want to observe network activity."
  dynamic["toggle"]?.text=if(LearnedLive.running)"Pause monitoring" else "Start monitoring"
  dynamic["traffic"]?.text="%,d packets observed".format(LearnedLive.packets)
  dynamic["checks"]?.text="%,d learned checks · %.0f min running".format(LearnedLive.inferences+b.optLong("snapshots"),LearnedLive.seconds/60)
  dynamic["reviews"]?.text=ObservationStore.count(this,"active").toString()+" activities to review"
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
    "queued"->"Advice will appear shortly"
    "running"->"Writing advice…"
    "complete"->if(selected.optJSONObject("explanation")?.optBoolean("generated_text_accepted")==true)"Advice from Llama" else "Advice ready"
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
 private var checkIsLink=false
 private fun acceptSharedText(source: Intent){
  sharedInput=source.getStringExtra(Intent.EXTRA_TEXT).orEmpty().take(32768)
  checkIsLink=sharedInput.trim().matches(Regex("(?:https?://|www\\.)\\S+"))
  checkRequestId="";source.removeExtra(Intent.EXTRA_TEXT)
 }
 override fun onNewIntent(next: Intent){super.onNewIntent(next);setIntent(next);configureTrace(next);if(next.action==Intent.ACTION_SEND){acceptSharedText(next);selectedId="";tab=1;build();return};if(next.getBooleanExtra("start_monitor",false) && !LearnedLive.running)startForegroundService(Intent(this,TsanetCaptureService::class.java));selectedId=next.getStringExtra("observation_id") ?: "";tab=if(selectedId.isNotEmpty())2 else 0;build()}
 override fun onResume(){super.onResume();SafetyAnalysisService.resume(this);ResourceMonitor.acquire(this,"screen");ui.post(tick)}
 override fun onPause(){ui.removeCallbacks(tick);ResourceMonitor.release("screen");super.onPause()}
 override fun onDestroy(){alive=false;local?.stop();super.onDestroy()}
 @Deprecated("Activity back API")
 override fun onBackPressed(){if(selectedId.isNotEmpty()){selectedId="";draftNote="";build()}else if(tab!=0){tab=0;build()}else super.onBackPressed()}
}
