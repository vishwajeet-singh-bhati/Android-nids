package nids.trafficlab

import android.app.*
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.net.URLDecoder
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONArray
import org.json.JSONObject

/** Intentionally vulnerable, disposable target. Only the verified controller is admitted. */
class LabService: Service(){
    @Volatile private var listener: ServerSocket?=null
    @Volatile private var stopping=false
    private var controller=""
    private val pending=Semaphore(16)
    private val resource=Semaphore(2)
    private val beaconStarted=AtomicBoolean()
    private lateinit var database: SQLiteDatabase
    private val main=Handler(Looper.getMainLooper())
    override fun onBind(intent: Intent?): IBinder?=null
    @Synchronized private fun event(kind: String,extra: JSONObject=JSONObject()){
        extra.put("event",kind).put("time_ms",System.currentTimeMillis())
        File(filesDir,"lab_events.jsonl").appendText(extra.toString()+"\n")
    }
    override fun onStartCommand(intent: Intent?,flags: Int,startId: Int): Int{
        if(intent?.action=="stop"){stopping=true;listener?.close();stopSelf();return START_NOT_STICKY}
        if(listener!=null)return START_NOT_STICKY
        controller=intent?.getStringExtra("controller") ?: "127.0.0.1"
        require(controller.matches(Regex("[0-9.]{7,15}")))
        val manager=getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("lab","Controlled attack target",NotificationManager.IMPORTANCE_LOW))
        startForeground(1,Notification.Builder(this,"lab").setContentTitle("NIDS isolated test target")
            .setContentText("Only $controller; bounded session; dummy data")
            .setSmallIcon(android.R.drawable.ic_menu_info_details).setOngoing(true).build())
        stopping=false
        database=SQLiteDatabase.create(null)
        database.execSQL("CREATE TABLE lab_data(value TEXT)")
        database.execSQL("INSERT INTO lab_data VALUES ('public-record'),('NIDS_SQLI_PROOF')")
        File(filesDir,"lab_events.jsonl").writeText("")
        Thread({
            val pool=Executors.newFixedThreadPool(8)
            val total=AtomicInteger()
            val until=System.currentTimeMillis()+15*60*1000L
            var failure=""
            try{
                val server=ServerSocket().apply{reuseAddress=true;bind(InetSocketAddress(43190),16);soTimeout=1000};listener=server
                File(filesDir,"lab_status.json").writeText(JSONObject().put("state","listening").put("controller",controller)
                    .put("port",43190).put("version","0.2.0").put("expires_ms",until).toString())
                while(!stopping && System.currentTimeMillis()<until && total.get()<512){
                    val client=try{server.accept()}catch(_: java.net.SocketTimeoutException){continue}
                    if(client.inetAddress.hostAddress!=controller || !pending.tryAcquire()){client.close();continue}
                    total.incrementAndGet()
                    pool.execute{try{handle(client)}finally{pending.release()}}
                }
            }catch(e: Exception){if(!stopping)failure=e.toString()}finally{
                stopping=true;try{listener?.close()}catch(_: Exception){};listener=null;pool.shutdownNow()
                database.close();stopForeground(STOP_FOREGROUND_REMOVE);stopSelf()
                File(filesDir,"lab_status.json").writeText(JSONObject().put("state",if(failure.isEmpty())"stopped" else "failed")
                    .put("error",failure).put("requests",total.get()).toString())
            }
        },"isolated-attack-target").start()
        return START_NOT_STICKY
    }
    private fun respond(socket: Socket,code: Int,value: String,type: String="application/json"){
        val body=value.toByteArray(Charsets.UTF_8)
        val title=when(code){200->"OK";202->"Accepted";401->"Unauthorized";503->"Service Unavailable";else->"Bad Request"}
        socket.getOutputStream().write(("HTTP/1.1 $code $title\r\nContent-Type: $type\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n").toByteArray())
        socket.getOutputStream().write(body);socket.getOutputStream().flush()
    }
    private fun handle(client: Socket){client.use{socket->
        socket.soTimeout=2500
        try{
            val reader=socket.getInputStream().bufferedReader()
            val first=reader.readLine()?.take(1200) ?: return
            var bytes=first.length
            while(bytes<4096){val line=reader.readLine() ?: break;bytes+=line.length;if(line.isEmpty())break}
            require(bytes<4096)
            val uri=URI(first.split(' ').getOrElse(1){"/"})
            val query=uri.rawQuery.orEmpty().split('&').filter{it.contains('=')}.associate{
                val fields=it.split('=',limit=2);URLDecoder.decode(fields[0],"UTF-8") to URLDecoder.decode(fields[1],"UTF-8")}
            when(uri.path){
                "/login"->{
                    val success=query["user"]=="nids-lab-user" && query["password"]=="nids-lab-27"
                    event(if(success)"login_success" else "login_failure")
                    respond(socket,if(success)200 else 401,JSONObject().put("authenticated",success).put("dummy_account",true).toString())
                }
                "/search"->{
                    // Intentional SQL injection, confined to this disposable in-memory database.
                    val values=JSONArray()
                    database.rawQuery("SELECT value FROM lab_data WHERE value = '${query["q"].orEmpty().take(400)}'",null).use{
                        while(it.moveToNext() && values.length()<20)values.put(it.getString(0))}
                    val proof=(0 until values.length()).any{values.getString(it)=="NIDS_SQLI_PROOF"}
                    event(if(proof)"sqli_confirmed" else "search",JSONObject().put("returned_rows",values.length()))
                    respond(socket,200,JSONObject().put("values",values).put("sqli_proof",proof).toString())
                }
                "/xss"->{
                    val input=query["q"].orEmpty().take(400)
                    val html="<html><body><div id='proof'></div>$input</body></html>"
                    event("xss_payload_received")
                    main.post{isolatedJavascript(html)}
                    respond(socket,200,html,"text/html")
                }
                "/hold"->{
                    if(!resource.tryAcquire()){
                        event("test_resource_denied");respond(socket,503,"{\"test_resource_exhausted\":true}")
                    }else try{event("test_resource_held");Thread.sleep(5000);respond(socket,200,"{\"released\":true}")}finally{resource.release()}
                }
                "/beacon-start"->{
                    if(beaconStarted.compareAndSet(false,true))Thread({beacon()},"controlled-beacon").start()
                    respond(socket,202,"{\"controlled_beacon_started\":true}")
                }
                else->{event("http_request");Thread.sleep(20);respond(socket,200,"{\"isolated_target\":true}")}
            }
        }catch(e: Exception){event("request_error",JSONObject().put("error",e.javaClass.simpleName))}
    }}
    @Suppress("SetJavaScriptEnabled") private fun isolatedJavascript(html: String){
        if(stopping)return
        try{
            val web=WebView(this)
            web.settings.javaScriptEnabled=true;web.settings.allowFileAccess=false;web.settings.allowContentAccess=false
            web.settings.blockNetworkLoads=true;web.settings.domStorageEnabled=false
            web.addJavascriptInterface(object{
                @JavascriptInterface fun mark(token: String){if(token=="NIDS_XSS_PROOF")event("xss_execution_confirmed")}
            },"LabProof")
            web.webViewClient=object: WebViewClient(){override fun onPageFinished(view: WebView,url: String){main.postDelayed({view.destroy()},1000)}}
            web.loadDataWithBaseURL("https://nids.invalid/",html,"text/html","UTF-8",null)
        }catch(e: Exception){event("xss_execution_error",JSONObject().put("error",e.javaClass.simpleName))}
    }
    private fun beacon(){
        repeat(12){index->
            if(stopping)return
            try{Socket().use{socket->
                socket.connect(InetSocketAddress(controller,43990),1500);socket.soTimeout=1500
                val command=socket.getInputStream().bufferedReader().readLine()?.take(16)
                if(command=="PING"){socket.getOutputStream().write("PONG\n".toByteArray());socket.getOutputStream().flush()
                    event("beacon_ping_pong",JSONObject().put("sequence",index))}
            }}catch(e: Exception){event("beacon_error",JSONObject().put("error",e.javaClass.simpleName))}
            try{Thread.sleep(3000)}catch(_: InterruptedException){return}
        }
    }
    override fun onDestroy(){stopping=true;try{listener?.close()}catch(_: Exception){};super.onDestroy()}
}
