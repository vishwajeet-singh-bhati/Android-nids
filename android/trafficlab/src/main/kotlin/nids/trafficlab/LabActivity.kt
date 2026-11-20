package nids.trafficlab

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.*

class LabActivity: Activity(){
    override fun onNewIntent(value: Intent){
        super.onNewIntent(value);intent=value
        if(value.getBooleanExtra("start_listener",false))startForegroundService(Intent(this,LabService::class.java)
            .putExtra("controller",value.getStringExtra("controller") ?: "127.0.0.1"))
    }
    override fun onCreate(state: Bundle?){
        super.onCreate(state)
        if(android.os.Build.VERSION.SDK_INT>=33)requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),1)
        val controller=intent.getStringExtra("controller") ?: "127.0.0.1"
        val view=LinearLayout(this).apply{orientation=LinearLayout.VERTICAL;setPadding(28,40,28,24)}
        view.addView(TextView(this).apply{text="NIDS Traffic Lab";textSize=26f})
        view.addView(TextView(this).apply{text="Isolated attack target for the owner's tests. Accepts only the specified work PC; stops after 15 minutes or 512 requests.\n\nController: $controller\nPort: 43190\n\nIncludes a dummy login, deliberately injectable in-memory database, isolated JavaScript proof, and a two-slot test resource. Uses invented data only. No shell commands or phone files are exposed. NIDS detection is evaluated separately.";textSize=16f})
        fun start(){startForegroundService(Intent(this,LabService::class.java).putExtra("controller",controller))}
        view.addView(Button(this).apply{text="Start bounded test listener";setOnClickListener{start()}})
        view.addView(Button(this).apply{text="Stop listener";setOnClickListener{startService(Intent(this@LabActivity,LabService::class.java).setAction("stop"))}})
        setContentView(view)
        if(intent.getBooleanExtra("start_listener",false))start()
    }
}
