package nids.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Resume only monitoring that the user previously enabled. */
class MonitorBootReceiver: BroadcastReceiver(){
    override fun onReceive(context: Context,intent: Intent){
        if(intent.action !in setOf(Intent.ACTION_BOOT_COMPLETED,Intent.ACTION_MY_PACKAGE_REPLACED))return
        if(context.getSharedPreferences("background_monitor",Context.MODE_PRIVATE).getBoolean("enabled",false)){
            try{context.startForegroundService(Intent(context,TsanetCaptureService::class.java))}catch(_: Exception){}
        }
    }
}
