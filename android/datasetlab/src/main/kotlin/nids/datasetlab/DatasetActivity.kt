package nids.datasetlab

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.TextView

class DatasetActivity: Activity(){
    private fun start(value: Intent){
        if(!value.getBooleanExtra("start_listener",false))return
        val service=Intent(this,DatasetService::class.java)
        for(key in listOf("controller","bind_address","session","user","password","bridge"))service.putExtra(key,value.getStringExtra(key))
        service.putExtra("port",value.getIntExtra("port",43191));service.putExtra("seed",value.getLongExtra("seed",1))
        startForegroundService(service)
    }
    override fun onNewIntent(value: Intent){super.onNewIntent(value);intent=value;start(value)}
    override fun onCreate(state: Bundle?){
        super.onCreate(state)
        if(android.os.Build.VERSION.SDK_INT>=33)requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),1)
        setContentView(TextView(this).apply{setPadding(32,60,32,30);textSize=18f
            text="NIDS dataset collection\n\nDisposable database, dummy accounts and isolated page rendering. Only this work PC is admitted. No phone files or shell are exposed. The listener stops after 15 minutes or 1,024 connections.\n\nActivity labels are recorded independently of NIDS predictions."})
        start(intent)
    }
}
