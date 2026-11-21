package nids.app
import android.content.Context
import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.util.UUID

/** Seven-day local incident/feedback history. User reports are not verified ground truth. */
object ObservationStore {
 private const val RETENTION=7L*24*60*60*1000
 private val helpers=HashMap<String,SQLiteOpenHelper>()
 @Synchronized private fun db(c: Context): SQLiteDatabase {
  val path=File(c.filesDir,"activity_history_v1.db").absolutePath
  return helpers.getOrPut(path){object: SQLiteOpenHelper(c,path,null,1){
   override fun onCreate(db: SQLiteDatabase){
    db.execSQL("CREATE TABLE observations(id TEXT PRIMARY KEY, kind TEXT, fingerprint TEXT, time_ms INTEGER, created_ms INTEGER, revision INTEGER, reviewed_revision INTEGER, disposition TEXT, explanation_status TEXT, body TEXT)")
    db.execSQL("CREATE INDEX obs_time ON observations(time_ms DESC)")
    db.execSQL("CREATE INDEX obs_group ON observations(fingerprint,time_ms DESC)")
    db.execSQL("CREATE TABLE feedback(id TEXT PRIMARY KEY,time_ms INTEGER,body TEXT)")
    db.execSQL("CREATE INDEX feedback_time ON feedback(time_ms)")
   }
   override fun onUpgrade(db: SQLiteDatabase,oldVersion: Int,newVersion: Int){}
  }.apply{setWriteAheadLoggingEnabled(true)}}.writableDatabase
 }
 @Synchronized fun close(c: Context){helpers.remove(File(c.filesDir,"activity_history_v1.db").absolutePath)?.close()}
 private fun prune(db: SQLiteDatabase){val cutoff=(System.currentTimeMillis()-RETENTION).toString();db.delete("observations","time_ms<?",arrayOf(cutoff));db.delete("feedback","time_ms<?",arrayOf(cutoff))}
 private fun put(db: SQLiteDatabase,row: JSONObject){
  val v=ContentValues().apply{
   put("id",row.getString("id"));put("kind",row.getString("kind"));put("fingerprint",row.optString("fingerprint",row.getString("kind")));put("time_ms",row.optLong("time_ms"));put("created_ms",row.optLong("created_ms"));put("revision",row.optInt("revision"));put("reviewed_revision",row.optJSONObject("feedback")?.optInt("revision") ?: 0);put("disposition",row.optString("disposition","active"));put("explanation_status",row.optString("explanation_status","queued"));put("body",row.toString())
  };db.insertWithOnConflict("observations",null,v,SQLiteDatabase.CONFLICT_REPLACE)
 }
 private fun where(filter: String)=when(filter){"active"->" AND disposition NOT IN ('dismissed','out_of_scope')";"dismissed"->" AND disposition='dismissed'";else->""}
 @Synchronized fun list(c: Context,limit: Int=50,filter: String="all",offset: Int=0): List<JSONObject>{
  val rows=ArrayList<JSONObject>();db(c).rawQuery("SELECT body FROM observations WHERE time_ms>=?"+where(filter)+" ORDER BY time_ms DESC,id DESC LIMIT ? OFFSET ?",arrayOf((System.currentTimeMillis()-RETENTION).toString(),limit.toString(),offset.toString())).use{cursor -> while(cursor.moveToNext())rows.add(JSONObject(cursor.getString(0)))}
  return rows.asReversed()
 }
 @Synchronized fun count(c: Context,filter: String="all"): Long=db(c).rawQuery("SELECT count(*) FROM observations WHERE time_ms>=?"+where(filter),arrayOf((System.currentTimeMillis()-RETENTION).toString())).use{it.moveToFirst();it.getLong(0)}
 @Synchronized fun get(c: Context,id: String): JSONObject?=db(c).rawQuery("SELECT body FROM observations WHERE id=? AND time_ms>=?",arrayOf(id,(System.currentTimeMillis()-RETENTION).toString())).use{if(it.moveToFirst())JSONObject(it.getString(0)) else null}
 @Synchronized fun record(c: Context,kind: String,count: Long,evidence: JSONObject): JSONObject{
  val db=db(c);prune(db);val now=System.currentTimeMillis();val fingerprint=evidence.optString("fingerprint",kind)
  val row=db.rawQuery("SELECT body FROM observations WHERE fingerprint=? AND disposition!='out_of_scope' AND time_ms>? AND created_ms>? ORDER BY time_ms DESC LIMIT 1",arrayOf(fingerprint,(now-30000).toString(),(now-RETENTION).toString())).use{if(it.moveToFirst())JSONObject(it.getString(0)) else null}
   ?:JSONObject().put("id",UUID.randomUUID().toString()).put("kind",kind).put("fingerprint",fingerprint).put("created_ms",now).put("revision",0).put("count",0).put("status","unconfirmed_anomaly").put("attack_verified",false).put("disposition","active").put("explanation_status","queued")
  row.put("revision",row.optInt("revision")+1).put("time_ms",now).put("time",now/1000.0).put("count",row.optLong("count")+count).put("model_evidence",evidence)
  val attribution=evidence.optJSONObject("attribution") ?: JSONObject().put("status","unknown").put("direction","unknown")
  row.put("attribution",attribution).put("attack_type","unverified").put("traffic_scope",evidence.optString("traffic_scope","external_network"))
  row.put("title",if(kind=="sustained_pattern")"Sustained traffic pattern" else "Unusual connection activity")
  row.put("observation",if(kind=="sustained_pattern")"A learned model found repeated traffic patterns across consecutive windows. Ordinary activity may also produce this." else "A learned model flagged connection patterns. Related flags are grouped into this activity.")
  row.put("safe_verification","If this activity is unfamiliar, review the named app when attribution is available, its permissions and recent installs. Review your network in Android Settings. Avoid entering passwords into unexpected prompts. You can disconnect an unfamiliar network manually if needed.")
  if(kind=="tsanet_pattern"){
   val category=evidence.optString("suspected_pattern","unusual network")
   row.put("title",if(category=="Unclassified")"Unusual network activity" else "Possible $category activity").put("attack_type",category)
    .put("observation",if(category=="Unclassified")"The binary model flagged this connection; diagnosis did not establish a specific type." else "The local models suggested this traffic pattern. This is an estimate from observed network statistics, not a confirmed attack.")
    .put("safe_verification",TsanetExplanationFacts.guidance(category))
   TsanetExplanationFacts.from(evidence)?.let{facts->
    row.put("title",HybridActivityNote.title(facts)).put("factual_note",HybridActivityNote.render(facts))
     .put("factual_note_revision",row.getInt("revision")).put("explanation_pipeline",HybridActivityNote.VERSION)
     .put("safe_verification",HybridActivityNote.guidance(facts))
   }
  }
  // A completed draft describes an older revision once new evidence arrives.
  // Preserve the running request until it returns, but never display/save it
  // against changed facts. The immediate note always describes this revision.
  if(row.has("explanation") && row.getJSONObject("explanation").optInt("evidence_revision",-1)!=row.getInt("revision"))row.remove("explanation")
  if(row.optString("disposition")=="dismissed")row.put("explanation_status","skipped")
  else if(row.optString("explanation_status")!="running")row.put("explanation_status","queued")
  put(db,row);return JSONObject(row.toString())
 }
 @Synchronized fun feedback(c: Context,id: String,revision: Int,label: String,note: String){
  require(label in setOf("expected","suspicious","unsure"));val database=db(c);val row=get(c,id) ?: error("Activity is no longer in the seven-day log")
  require(row.getInt("revision")==revision){"Activity changed. Refresh it before responding."}
  val now=System.currentTimeMillis();val event=JSONObject().put("schema",1).put("feedback_id",UUID.randomUUID().toString()).put("observation_id",id).put("evidence_revision",revision).put("time_ms",now).put("user_label",label).put("note",note.take(300)).put("verified_ground_truth",false).put("evidence_snapshot",JSONObject(row.toString()))
  database.insertOrThrow("feedback",null,ContentValues().apply{put("id",event.getString("feedback_id"));put("time_ms",now);put("body",event.toString())})
  row.put("feedback",JSONObject().put("label",label).put("revision",revision).put("time_ms",now)).put("disposition",if(label=="expected")"dismissed" else if(row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL)"out_of_scope" else "active")
  if(label=="expected" && row.optString("explanation_status") in setOf("queued","running"))row.put("explanation_status","skipped")
  if(NetworkObservationPolicy.explanationAllowed(row) && label!="expected" && row.optString("explanation_status") in setOf("skipped","cancelled","failed"))row.put("explanation_status","queued")
  put(database,row);prune(database)
 }
 @Synchronized fun saveExplanation(c: Context,id: String,revision: Int,result: JSONObject): Boolean{
  val row=get(c,id) ?: return false
  if(!NetworkObservationPolicy.explanationAllowed(row)){row.put("explanation_status",if(row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL)"not_applicable" else "skipped");put(db(c),row);return false}
  if(row.getInt("revision")!=revision){row.put("explanation_status","queued");put(db(c),row);return false}
  row.put("explanation",JSONObject(result.toString()).put("evidence_revision",revision)).put("explanation_status","complete");put(db(c),row)
  return true
 }
 @Synchronized fun explanationState(c: Context,id: String,state: String,error: String=""){
  val row=get(c,id) ?: return
  if(row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL)row.put("explanation_status","not_applicable")
  else if(row.optString("disposition")=="dismissed" && state!="complete")row.put("explanation_status","skipped") else row.put("explanation_status",state)
  if(state=="running")row.put("explanation_attempts",row.optInt("explanation_attempts")+1)
  row.put("explanation_error",error);put(db(c),row)
 }
 @Synchronized fun nextQueued(c: Context): JSONObject?=db(c).rawQuery("SELECT body FROM observations WHERE explanation_status='queued' AND disposition NOT IN ('dismissed','out_of_scope') AND time_ms>=? ORDER BY created_ms ASC LIMIT 1",arrayOf((System.currentTimeMillis()-RETENTION).toString())).use{if(it.moveToFirst())JSONObject(it.getString(0)) else null}
 @Synchronized fun queuedCount(c: Context): Long=db(c).rawQuery("SELECT count(*) FROM observations WHERE explanation_status IN ('queued','running') AND disposition NOT IN ('dismissed','out_of_scope') AND time_ms>=?",arrayOf((System.currentTimeMillis()-RETENTION).toString())).use{it.moveToFirst();it.getLong(0)}
 @Synchronized fun reclassifyDeviceLocal(c: Context): List<String>{
  val database=db(c);val rows=ArrayList<JSONObject>();val ids=ArrayList<String>()
  database.rawQuery("SELECT body FROM observations WHERE kind='tsanet_pattern' AND time_ms>=?",arrayOf((System.currentTimeMillis()-RETENTION).toString())).use{while(it.moveToNext())rows.add(JSONObject(it.getString(0)))}
  database.beginTransaction()
  try{
   for(row in rows){
    val evidence=row.optJSONObject("model_evidence") ?: continue
    if(!NetworkObservationPolicy.localEvidence(evidence))continue
    ids.add(row.getString("id"))
    if(row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL)continue
    row.put("original_model_assessment",JSONObject().put("title",row.optString("title")).put("attack_type",row.optString("attack_type"))
     .put("revision",row.optInt("revision")).put("explanation",row.optJSONObject("explanation")))
     .put("traffic_scope",NetworkObservationPolicy.LOCAL).put("scope_reclassified_ms",System.currentTimeMillis())
     .put("revision",row.optInt("revision")+1).put("explanation_status","not_applicable")
     .put("title","On-device communication").put("attack_type","not_assessed")
     .put("observation","This connection stayed inside the phone and is outside the default external-network intrusion assessment.")
     .put("factual_note",NetworkObservationPolicy.localNote(evidence)).put("safe_verification","Review installed apps or developer tools if this local activity is unfamiliar. It has not been classified as safe.")
    if(row.optString("disposition")!="dismissed")row.put("disposition","out_of_scope")
    row.remove("explanation");put(database,row)
   }
   database.setTransactionSuccessful()
  }finally{database.endTransaction()}
  return ids
 }
 @Synchronized fun recoverQueue(c: Context){
  val database=db(c);val rows=ArrayList<JSONObject>();database.rawQuery("SELECT body FROM observations WHERE explanation_status='running'",null).use{while(it.moveToNext())rows.add(JSONObject(it.getString(0)))}
  for(row in rows){row.put("explanation_status",if(row.optString("traffic_scope")==NetworkObservationPolicy.LOCAL)"not_applicable" else if(!NetworkObservationPolicy.explanationAllowed(row))"skipped" else "queued");put(database,row)};prune(database)
 }
 @Synchronized fun export(c: Context,stream: OutputStream,metadata: JSONObject){
  val writer=stream.bufferedWriter();writer.write(metadata.toString().removeSuffix("}"));var needsComma=metadata.length()>0;val cutoff=(System.currentTimeMillis()-RETENTION).toString()
  for((name,query) in listOf("observations" to "SELECT body FROM observations WHERE time_ms>=? ORDER BY time_ms DESC","feedback" to "SELECT body FROM feedback WHERE time_ms>=? ORDER BY time_ms ASC")){
   if(needsComma)writer.write(",");needsComma=true;writer.write("\"$name\":[");var first=true
   db(c).rawQuery(query,arrayOf(cutoff)).use{while(it.moveToNext()){if(!first)writer.write(",");writer.write(it.getString(0));first=false}}
   writer.write("]")
  };writer.write("}");writer.flush()
 }
 @Synchronized fun migrate(c: Context){
  val database=db(c);prune(database)
  val marker=File(c.filesDir,"history_sqlite_migrated")
  if(marker.exists())return
  val old=try{JSONArray(File(c.filesDir,"observations_v1.json").readText())}catch(_: Exception){JSONArray()}
  for(i in 0 until old.length()){
   val row=old.getJSONObject(i);if(row.optLong("time_ms")<System.currentTimeMillis()-RETENTION)continue
   row.put("fingerprint",row.optString("kind")+"|historical|"+row.getString("id")).put("explanation_status",if(row.has("explanation"))"complete" else "manual_only").put("disposition",if(row.optJSONObject("feedback")?.optString("label")=="expected")"dismissed" else "active");put(database,row)
  }
  File(c.filesDir,"feedback_v1.jsonl").takeIf{it.exists()}?.forEachLine{line -> try{val row=JSONObject(line);if(row.optLong("time_ms")>=System.currentTimeMillis()-RETENTION)database.insertWithOnConflict("feedback",null,ContentValues().apply{put("id",row.getString("feedback_id"));put("time_ms",row.getLong("time_ms"));put("body",line)},SQLiteDatabase.CONFLICT_IGNORE)}catch(_: Exception){}}
  marker.writeText("7-day SQLite history initialized")
 }
}
