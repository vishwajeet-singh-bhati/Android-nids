package nids.app
import android.app.*
import android.content.Context
import android.content.Intent
import org.json.JSONObject

object ObservationNotifications {
 fun show(context: Context,row: JSONObject){
  if(!NetworkObservationPolicy.explanationAllowed(row))return
  val manager=context.getSystemService(NotificationManager::class.java)
  val safety=SafetyNote.from(row.optJSONObject("model_evidence"))
  val urgent=safety?.optString("risk_level")=="high"
  val channel=if(safety==null)"network_review_v1" else if(urgent)"safety_high_risk_v1" else "safety_review_v1"
  manager.createNotificationChannel(NotificationChannel(channel,if(safety==null)"Network activity to review" else if(urgent)"Important message and link warnings" else "Message and link warnings",if(urgent)NotificationManager.IMPORTANCE_HIGH else NotificationManager.IMPORTANCE_DEFAULT))
  val id=row.getString("id");val attribution=row.optJSONObject("attribution");val direction=attribution?.optString("direction") ?: "unknown"
  val label=attribution?.optString("app_label","App unknown") ?: "App unknown"
  val activity=row.optString("title","Network activity to review")
  val title=if(row.optJSONObject("model_evidence")?.optBoolean("test_only")==true)"TEST - "+activity else if(attribution?.optString("status")=="best_effort")"$label: $activity" else activity
  val text=HybridActivityNote.display(row)
  val open=PendingIntent.getActivity(context,id.hashCode(),Intent(context,LearnedNetworkActivity::class.java).putExtra("observation_id",id).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  val notification=Notification.Builder(context,channel).setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(title.take(90)).setContentText(text.substringAfter("What happened\n").substringBefore("\n\n")).setStyle(Notification.BigTextStyle().bigText(text)).setContentIntent(open).setOnlyAlertOnce(true).setAutoCancel(true).setVisibility(Notification.VISIBILITY_PRIVATE).setGroup("nids.activity").build()
  try{manager.notify(id.hashCode(),notification)}catch(_: SecurityException){}
 }
}
