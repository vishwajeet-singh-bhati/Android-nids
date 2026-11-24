package nids.app
import android.content.Context
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.io.File

/** Persistent FIFO, one isolated Llama worker at a time. Notifications do not wait for it. */
object AutomaticExplanations {
 private val ui=Handler(Looper.getMainLooper())
 fun pump(context: Context){val app=context.applicationContext;ui.post{
  if(LlamaLive.running)return@post
  val next=ObservationStore.nextQueued(app) ?: return@post
  start(app,next)
 }}
 fun request(context: Context,row: JSONObject){
  if(LlamaLive.running)return
  ObservationStore.explanationState(context,row.getString("id"),"queued")
  start(context.applicationContext,ObservationStore.get(context,row.getString("id")) ?: row)
 }
 private fun start(app: Context,row: JSONObject){
  val id=row.getString("id");val revision=row.getInt("revision")
  if(!NetworkObservationPolicy.explanationAllowed(row))return
  try{
   ObservationStore.explanationState(app,id,"running")
   LlamaClient.explain(app,JSONObject(row.toString())){report,error ->
    if(report!=null){
     val saved=ObservationStore.saveExplanation(app,id,report.optInt("evidence_revision_used",revision),report)
     if(saved)File(app.filesDir,"last_local_explanation.json").writeText(report.toString(2))
    }else{
     val attempts=ObservationStore.get(app,id)?.optInt("explanation_attempts") ?: 2
     val cancelled=error?.contains("cancel",true)==true
     ObservationStore.explanationState(app,id,if(cancelled)"cancelled" else if(attempts<2)"queued" else "failed",error ?: "Local model unavailable")
    }
    ObservationStore.get(app,id)?.let{ObservationNotifications.show(app,it)}
    ui.postDelayed({pump(app)},1000)
   }
  }catch(e: Exception){ObservationStore.explanationState(app,id,"failed",e.message ?: "Local model unavailable")}
 }
 fun dismiss(context: Context,id: String){
  context.getSystemService(android.app.NotificationManager::class.java).cancel(id.hashCode())
  if(LlamaLive.running && LlamaLive.observationId==id)LlamaClient.cancel("Explanation cancelled after dismissal")
  if(ObservationStore.queuedCount(context)==0L)LlamaClient.releaseIfIdle()
 }
}
