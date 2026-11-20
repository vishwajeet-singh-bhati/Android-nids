package nids.app
import android.app.*
import android.content.Context
import android.content.Intent
import org.json.JSONObject

object ObservationNotifications {
 fun show(context: Context,row: JSONObject){
  if(row.optString("disposition")=="dismissed")return
  val manager=context.getSystemService(NotificationManager::class.java)
  manager.createNotificationChannel(NotificationChannel("network_review_v1","Network activity to review",NotificationManager.IMPORTANCE_DEFAULT))
  val id=row.getString("id");val attribution=row.optJSONObject("attribution");val direction=attribution?.optString("direction") ?: "unknown"
  val label=attribution?.optString("app_label","App unknown") ?: "App unknown"
  val title=if(direction=="incoming")"Incoming activity to review" else if(attribution?.optString("status")=="best_effort")"$label: activity to review" else "Network activity to review"
  val explanation=row.optJSONObject("explanation")
  val text=if(explanation!=null)explanation.optString("display") else when(row.optString("explanation_status")){"running"->"Unconfirmed pattern. Explaining locally…";"queued"->"Unconfirmed pattern. Local explanation queued.";else->"Unconfirmed pattern. Review the evidence and next steps."}
  val open=PendingIntent.getActivity(context,id.hashCode(),Intent(context,LearnedNetworkActivity::class.java).putExtra("observation_id",id).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  val notification=Notification.Builder(context,"network_review_v1").setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle(title.take(90)).setContentText(text).setStyle(Notification.BigTextStyle().bigText(text)).setContentIntent(open).setOnlyAlertOnce(true).setAutoCancel(true).setVisibility(Notification.VISIBILITY_PRIVATE).setGroup("nids.activity").build()
  try{manager.notify(id.hashCode(),notification)}catch(_: SecurityException){}
 }
}
