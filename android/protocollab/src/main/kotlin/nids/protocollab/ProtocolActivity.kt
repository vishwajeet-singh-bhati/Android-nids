package nids.protocollab

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.*
import java.io.File
import nids.lab.LabServer

class ProtocolActivity: Activity(){
    override fun onCreate(state: Bundle?){
        super.onCreate(state)
        if(android.os.Build.VERSION.SDK_INT>=33)requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),1)
        val view=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(28,40,28,24)}
        view.addView(TextView(this).apply{text="NIDS Protocol Lab";textSize=26f})
        view.addView(TextView(this).apply{text="Disposable FTP/SSH dummy accounts and a two-slot application resource. No shell, file transfers, forwarding or real phone accounts.\n\nListeners run only after a manual work-PC test command. Each session ends within15minutes and accepts only its listed lab PCs. The command-response emulator accepts only PING and STATUS. Monitoring and model alerts belong to NIDS, separately.";textSize=16f})
        view.addView(Button(this).apply{text="Stop lab session";setOnClickListener{stopService(Intent(this@ProtocolActivity,ProtocolService::class.java))}})
        setContentView(view);launch(intent)
    }
    override fun onNewIntent(value: Intent){super.onNewIntent(value);intent=value;launch(value)}
    private fun launch(value: Intent){
        File(filesDir,"last_launch.json").writeText(LabServer.json(LabServer.fields("validate_only",value.getBooleanExtra("validate_only",false),"start_listener",value.getBooleanExtra("start_listener",false))))
        if(value.getBooleanExtra("validate_only",false))Thread({
            val report=try{LabServer.platformCheck(filesDir.absolutePath)}catch(e: Throwable){LabServer.fields("passed",false,"error",e.toString(),"stack",e.stackTraceToString(),"listeners_started",0,"network_requests_sent",0)}
            File(filesDir,"platform_check.json").writeText(LabServer.json(report))
        },"protocol-platform-check").start()
        if(value.getBooleanExtra("start_listener",false))startForegroundService(Intent(this,ProtocolService::class.java)
            .putExtra("bind",value.getStringExtra("bind")).putExtra("sources",value.getStringExtra("sources"))
            .putExtra("receiver",value.getStringExtra("receiver")).putExtra("session",value.getStringExtra("session")))
    }
}
