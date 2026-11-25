package nids.protocollab

import android.app.*
import android.content.Intent
import android.os.IBinder
import android.os.Handler
import android.os.Looper
import nids.lab.LabServer
import java.io.File

class ProtocolService: Service(){
    @Volatile private var lab: LabServer?=null
    private val handler=Handler(Looper.getMainLooper())
    private val expiry=Runnable{stopSelf()}
    override fun onBind(intent: Intent?): IBinder?=null
    override fun onStartCommand(intent: Intent?,flags: Int,startId: Int): Int{
        if(lab!=null)return START_NOT_STICKY
        val bind=intent?.getStringExtra("bind") ?: return START_NOT_STICKY
        val sources=intent.getStringExtra("sources")?.split(',')?.toSet() ?: return START_NOT_STICKY
        val receiver=intent.getStringExtra("receiver") ?: return START_NOT_STICKY
        val session=intent.getStringExtra("session") ?: return START_NOT_STICKY
        require(session.matches(Regex("[A-Za-z0-9_-]{8,80}")))
        val manager=getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("protocol_lab","Owned-device protocol tests",NotificationManager.IMPORTANCE_LOW))
        startForeground(1,Notification.Builder(this,"protocol_lab").setContentTitle("NIDS protocol test target")
            .setContentText("Bounded dummy services; manual session $session").setSmallIcon(android.R.drawable.ic_menu_info_details).setOngoing(true).build())
        File(filesDir,"events.jsonl").writeText("")
        Thread({try{
            LabServer.configureAndroid(filesDir.absolutePath)
            val connectivity=getSystemService(android.net.ConnectivityManager::class.java)
            val wifi=connectivity.allNetworks.filter{network->
                connectivity.getNetworkCapabilities(network)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI)==true &&
                    connectivity.getLinkProperties(network)?.linkAddresses?.any{it.address.hostAddress==bind}==true
            }.singleOrNull() ?: error("The configured lab Wi-Fi network is unavailable")
            val server=LabServer(bind,sources,receiver,{row->synchronized(this){File(filesDir,"events.jsonl").appendText(LabServer.json(row)+"\n")}},wifi.socketFactory)
            lab=server;server.start(LabServer.HTTP,LabServer.FTP,LabServer.SSH)
            val status=server.status();status["session"]=session;status["outbound_transport"]="WIFI";File(filesDir,"status.json").writeText(LabServer.json(status))
            handler.postDelayed(expiry,15*60*1000L)
        }catch(e: Throwable){
            File(filesDir,"status.json").writeText(LabServer.json(LabServer.fields("state","failed","session",session,"error",e.toString())))
            stopSelf()
        }},"protocol-lab-start").start()
        return START_NOT_STICKY
    }
    override fun onDestroy(){handler.removeCallbacks(expiry);lab?.close();lab=null;super.onDestroy()}
}
