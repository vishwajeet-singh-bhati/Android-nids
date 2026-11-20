package nids.datasetlab

import android.app.*
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.os.*
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import java.io.File
import java.net.*
import java.util.Random
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import org.json.JSONArray
import org.json.JSONObject

/** Bounded dummy target; ground truth is out-of-band and keyed to the actual socket. */
class DatasetService: Service(){
    @Volatile private var stopping=false
    @Volatile private var listener: ServerSocket?=null
    private var session="";private var controller="";private var bindAddress="";private var port=0
    private var user="";private var password="";private var bridge=""
    private var publicValue="";private var privateValue=""
    private lateinit var database: SQLiteDatabase
    private val main=Handler(Looper.getMainLooper())
    private val capacity=Semaphore(16)
    private val resource=Semaphore(2)
    private val webViews=HashSet<WebView>()
    override fun onBind(intent: Intent?): IBinder?=null
    @Synchronized private fun event(kind: String,connection: JSONObject?=null,extra: JSONObject=JSONObject()){
        extra.put("event",kind).put("time_ms",System.currentTimeMillis()).put("session",session)
        if(connection!=null)extra.put("connection",JSONObject(connection.toString()))
        File(filesDir,"events.jsonl").appendText(extra.toString()+"\n")
    }
    private fun privateV4(value: String): Boolean = value.matches(Regex("[0-9.]{7,15}")) && InetAddress.getByName(value).let{it is Inet4Address && it.isSiteLocalAddress}
    override fun onStartCommand(value: Intent?,flags: Int,startId: Int): Int{
        if(listener!=null)return START_NOT_STICKY
        require(value!=null)
        controller=value.getStringExtra("controller").orEmpty();bindAddress=value.getStringExtra("bind_address").orEmpty()
        session=value.getStringExtra("session").orEmpty();port=value.getIntExtra("port",43191)
        user=value.getStringExtra("user").orEmpty();password=value.getStringExtra("password").orEmpty();bridge=value.getStringExtra("bridge").orEmpty()
        require(privateV4(controller) && privateV4(bindAddress) && controller!=bindAddress)
        require(port in 43191..43199 && session.matches(Regex("[a-zA-Z0-9_-]{8,80}")))
        require(user.matches(Regex("[a-z0-9]{4,30}")) && password.matches(Regex("[a-z0-9]{6,40}")) && bridge.matches(Regex("b[a-f0-9]{8}")))
        val manager=getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("dataset","Bounded dataset target",NotificationManager.IMPORTANCE_LOW))
        startForeground(1,Notification.Builder(this,"dataset").setContentTitle("NIDS dataset target")
            .setContentText("Work PC only; disposable data; 15-minute limit").setSmallIcon(android.R.drawable.ic_lock_idle_lock).build())
        val random=Random(value.getLongExtra("seed",1));fun word(n: Int)=(0 until n).map{('a'.code+random.nextInt(26)).toChar()}.joinToString("")
        publicValue=word(24+random.nextInt(48));privateValue=word(publicValue.length)
        File(filesDir,"events.jsonl").writeText("");stopping=false
        database=SQLiteDatabase.create(null)
        database.execSQL("CREATE TABLE items(value TEXT)")
        database.execSQL("INSERT INTO items VALUES (?),(?)",arrayOf(publicValue,privateValue))
        Thread({
            val pool=Executors.newFixedThreadPool(8);var total=0
            val deadline=System.currentTimeMillis()+900000
            try{
                val server=ServerSocket().apply{reuseAddress=true;bind(InetSocketAddress(bindAddress,port),16);soTimeout=1000};listener=server
                File(filesDir,"status.json").writeText(JSONObject().put("state","listening").put("version","0.1.0")
                    .put("controller",controller).put("bind_address",bindAddress).put("port",port).put("session",session)
                    .put("public_value",publicValue).put("expires_ms",deadline).toString())
                while(!stopping && System.currentTimeMillis()<deadline && total<1024){
                    val socket=try{server.accept()}catch(_: SocketTimeoutException){continue}
                    if(socket.inetAddress.hostAddress!=controller || !capacity.tryAcquire()){socket.close();continue}
                    total++
                    val connection=JSONObject().put("protocol",6).put("source",socket.inetAddress.hostAddress).put("sport",socket.port)
                        .put("destination",socket.localAddress.hostAddress).put("dport",socket.localPort).put("accepted_ms",System.currentTimeMillis())
                        .put("connection_id","$session-$total")
                    event("connection_accepted",connection)
                    pool.execute{try{handle(socket,connection)}finally{capacity.release()}}
                }
            }catch(error: Exception){event("listener_error",extra=JSONObject().put("error",error.javaClass.simpleName))}
            finally{stopping=true;try{listener?.close()}catch(_: Exception){};listener=null;pool.shutdownNow();database.close();stopForeground(STOP_FOREGROUND_REMOVE);stopSelf()}
        },"dataset-target").start()
        return START_NOT_STICKY
    }
    private fun respond(socket: Socket,connection: JSONObject,code: Int,text: String,type: String="application/json"){
        val body=text.toByteArray(Charsets.UTF_8)
        socket.getOutputStream().write(("HTTP/1.1 $code Response\r\nContent-Type: $type\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n").toByteArray())
        socket.getOutputStream().write(body);socket.getOutputStream().flush()
        event("response_sent",connection,JSONObject().put("status",code).put("body_bytes",body.size))
    }
    private fun handle(socket: Socket,connection: JSONObject){socket.use{
        socket.soTimeout=4000
        try{
            val reader=socket.getInputStream().bufferedReader();val first=reader.readLine()?.take(1200) ?: return
            var bytes=first.length
            while(bytes<4096){val line=reader.readLine() ?: break;bytes+=line.length;if(line.isEmpty())break};require(bytes<4096)
            val uri=URI(first.split(' ').getOrElse(1){"/"})
            val query=uri.rawQuery.orEmpty().split('&').filter{it.contains('=')}.associate{
                val fields=it.split('=',limit=2);URLDecoder.decode(fields[0],"UTF-8") to URLDecoder.decode(fields[1],"UTF-8")}
            event("request_received",connection,JSONObject().put("method",first.substringBefore(' ')).put("route",uri.path))
            when(uri.path){
                "/login"->{
                    val name=query["user"].orEmpty();val valid=(name==user || (0..7).any{name==user+it}) && query["password"]==password
                    event(if(valid)"login_success" else "login_failure",connection,JSONObject().put("account",name.take(40)))
                    respond(socket,connection,if(valid)200 else 401,JSONObject().put("authenticated",valid).toString())
                }
                "/search"->{
                    val rows=JSONArray()
                    database.rawQuery("SELECT value FROM items WHERE value = '${query["q"].orEmpty().take(400)}'",null).use{cursor->
                        while(cursor.moveToNext() && rows.length()<20)rows.put(cursor.getString(0))}
                    val unauthorized=(0 until rows.length()).any{rows.getString(it)==privateValue}
                    event(if(unauthorized)"sql_effect_confirmed" else "search_completed",connection,JSONObject().put("returned_rows",rows.length()).put("unauthorized_row",unauthorized))
                    respond(socket,connection,200,JSONObject().put("values",rows).toString())
                }
                "/page"->{
                    val html="<html><body>${query["q"].orEmpty().take(400)}</body></html>"
                    main.post{render(html,connection)}
                    event("page_requested",connection);respond(socket,connection,200,html,"text/html")
                }
                "/hold"->{
                    if(resource.tryAcquire())try{event("resource_acquired",connection);Thread.sleep(3000);respond(socket,connection,200,"{}")}
                    finally{resource.release();event("resource_released",connection)}
                    else{event("resource_denied",connection);respond(socket,connection,503,"{}")}
                }
                "/service-error"->{event("ordinary_service_error",connection);respond(socket,connection,503,"{}")}
                else->{event("normal_request",connection);respond(socket,connection,200,JSONObject().put("value",query["q"].orEmpty().take(300)).toString())}
            }
        }catch(error: Exception){event("request_error",connection,JSONObject().put("error",error.javaClass.simpleName))}
        finally{event("connection_closed",connection)}
    }}
    private fun render(html: String,connection: JSONObject){
        if(stopping)return
        try{
            val web=WebView(this);webViews.add(web)
            web.settings.javaScriptEnabled=true;web.settings.allowFileAccess=false;web.settings.allowContentAccess=false
            web.settings.blockNetworkLoads=true
            web.addJavascriptInterface(object{
                @JavascriptInterface fun done(value: Int){if(value==1)event("xss_effect_confirmed",connection)}
            },bridge)
            web.webViewClient=object: WebViewClient(){override fun onPageFinished(view: WebView,url: String){
                event("page_rendered",connection);main.postDelayed({webViews.remove(view);view.destroy()},1500)
            }}
            web.loadDataWithBaseURL("https://dataset.invalid/",html,"text/html","UTF-8",null)
            main.postDelayed({if(webViews.remove(web))web.destroy()},6000)
        }catch(error: Exception){event("page_error",connection,JSONObject().put("error",error.javaClass.simpleName))}
    }
    override fun onDestroy(){
        stopping=true;try{listener?.close()}catch(_: Exception){}
        main.post{webViews.toList().forEach{it.destroy()};webViews.clear()};super.onDestroy()
    }
}
