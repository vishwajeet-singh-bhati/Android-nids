package nids.lab;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.RejectAllForwardingFilter;

/** Disposable protocol targets: invented accounts, no shell/files/forwarding. */
public final class LabServer implements AutoCloseable {
    public static void configureAndroid(String directory){
        org.apache.sshd.common.util.OsUtils.setAndroid(true);
        org.apache.sshd.common.util.io.PathUtils.setUserHomeFolderResolver(()->java.nio.file.Paths.get(directory));
        org.apache.sshd.common.util.OsUtils.setCurrentWorkingDirectoryResolver(()->java.nio.file.Paths.get(directory));
        org.apache.sshd.common.util.OsUtils.setCurrentUser(USER);
    }
    public static Map<String,Object> platformCheck(String directory) throws Exception {
        configureAndroid(directory);SshServer server=SshServer.setUpDefaultServer();server.close(true);
        try(java.nio.channels.AsynchronousServerSocketChannel channel=java.nio.channels.AsynchronousServerSocketChannel.open()){
            if(channel.getLocalAddress()!=null)throw new IllegalStateException("Preflight unexpectedly bound a listener");
        }
        KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);g.generateKeyPair();
        return fields("passed",true,"listeners_started",0,"network_requests_sent",0,"ssh_factory_and_rsa_available",true,"nio_acceptor_available",true);
    }
    public static final String USER="nids-lab-user", PASSWORD="nids-lab-valid";
    public static final int HTTP=43194, FTP=43195, SSH=43196, RECEIVER=43991;
    private final Set<String> allowed;
    private final String bind,receiver;
    private final javax.net.SocketFactory outboundSockets;
    private final Consumer<Map<String,Object>> sink;
    private final AtomicInteger connections=new AtomicInteger();
    private final Semaphore resource=new Semaphore(2);
    private final AtomicBoolean botStarted=new AtomicBoolean();
    private final List<ServerSocket> listeners=new CopyOnWriteArrayList<>();
    private final ThreadPoolExecutor workers=new ThreadPoolExecutor(8,8,0,TimeUnit.SECONDS,new ArrayBlockingQueue<>(24));
    private final ScheduledExecutorService timer=Executors.newSingleThreadScheduledExecutor();
    private final long until=System.currentTimeMillis()+15*60*1000L;
    private volatile boolean stopping;
    private SshServer ssh;
    private int httpPort,ftpPort,sshPort;
    private String fingerprint;
    public LabServer(String bind,Set<String> allowed,String receiver,Consumer<Map<String,Object>> sink){
        this(bind,allowed,receiver,sink,javax.net.SocketFactory.getDefault());
    }
    public LabServer(String bind,Set<String> allowed,String receiver,Consumer<Map<String,Object>> sink,javax.net.SocketFactory outboundSockets){
        if(allowed.isEmpty()||allowed.size()>4)throw new IllegalArgumentException("One to four allowed sources required");
        for(String ip:allowed)validate(ip);validate(bind);validate(receiver);
        this.bind=bind;this.allowed=new HashSet<>(allowed);this.receiver=receiver;this.sink=sink;
        this.outboundSockets=java.util.Objects.requireNonNull(outboundSockets);
    }
    private static void validate(String ip){
        if(!ip.matches("[0-9.]{7,15}"))throw new IllegalArgumentException("IPv4 literals only");
        try{InetAddress a=InetAddress.getByName(ip);if(!a.isSiteLocalAddress()&&!a.isLoopbackAddress())throw new IllegalArgumentException("Private lab addresses only");}
        catch(IOException e){throw new IllegalArgumentException(e);}
    }
    private synchronized void event(String kind,Socket socket,Map<String,Object> extra){
        Map<String,Object> row=new LinkedHashMap<>();row.put("event",kind);row.put("time_ms",System.currentTimeMillis());
        if(socket!=null){row.put("peer",socket.getInetAddress().getHostAddress());row.put("peer_port",socket.getPort());row.put("local_port",socket.getLocalPort());}
        row.putAll(extra);sink.accept(row);
    }
    public static Map<String,Object> fields(Object... values){Map<String,Object> out=new LinkedHashMap<>();for(int i=0;i<values.length;i+=2)out.put((String)values[i],values[i+1]);return out;}
    public synchronized void start(int http,int ftp,int sshPort) throws Exception {
        if(!listeners.isEmpty())throw new IllegalStateException("Already started");
        try{
            httpPort=listen(http,false);ftpPort=listen(ftp,true);
            KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);KeyPair pair=generator.generateKeyPair();
            fingerprint=KeyUtils.getFingerPrint(pair.getPublic());
            ssh=SshServer.setUpDefaultServer();ssh.setIoServiceFactoryFactory(new org.apache.sshd.common.io.nio2.Nio2ServiceFactoryFactory());ssh.setHost(bind);ssh.setPort(sshPort);
            ssh.setKeyPairProvider(KeyPairProvider.wrap(pair));
            ssh.setForwardingFilter(RejectAllForwardingFilter.INSTANCE);
            ssh.setShellFactory(null);ssh.setCommandFactory(null);ssh.setSubsystemFactories(Collections.emptyList());
            ssh.setPasswordAuthenticator((user,password,session)->{
                InetSocketAddress peer=(InetSocketAddress)session.getIoSession().getRemoteAddress();
                boolean accepted=allowed.contains(peer.getAddress().getHostAddress())&&USER.equals(user)&&PASSWORD.equals(password);
                event(accepted?"ssh_login_success":"ssh_login_failure",null,fields("peer",peer.getAddress().getHostAddress(),"peer_port",peer.getPort(),"local_port",this.sshPort,"dummy_account",true));
                return accepted;
            });
            ssh.setPublickeyAuthenticator((user,key,session)->false);ssh.setKeyboardInteractiveAuthenticator(null);
            ssh.addSessionListener(new SessionListener(){@Override public void sessionCreated(Session session){
                InetSocketAddress peer=(InetSocketAddress)session.getIoSession().getRemoteAddress();
                if(!allowed.contains(peer.getAddress().getHostAddress())||connections.incrementAndGet()>512||stopping)session.close(true);
            }});
            ssh.start();this.sshPort=ssh.getPort();
            timer.schedule(()->{try{close();}catch(Exception ignored){}},15,TimeUnit.MINUTES);
            event("target_started",null,fields("http_port",httpPort,"ftp_port",ftpPort,"ssh_port",this.sshPort,"expires_ms",until));
        }catch(Exception e){close();throw e;}
    }
    private int listen(int port,boolean ftp) throws IOException {
        ServerSocket server=new ServerSocket();server.setReuseAddress(true);server.bind(new InetSocketAddress(bind,port),16);server.setSoTimeout(1000);listeners.add(server);
        Thread thread=new Thread(()->{
            while(!stopping&&System.currentTimeMillis()<until){
                Socket client=null;
                try{
                    client=server.accept();
                    if(!allowed.contains(client.getInetAddress().getHostAddress())||connections.incrementAndGet()>512){client.close();continue;}
                    client.setSoTimeout(4000);Socket accepted=client;
                    workers.execute(()->{try(Socket socket=accepted){if(ftp)ftp(socket);else http(socket);}catch(Exception e){event("connection_error",accepted,fields("type",e.getClass().getSimpleName()));}});
                }catch(SocketTimeoutException ignored){}catch(RejectedExecutionException e){if(client!=null)try{client.close();}catch(IOException ignored){}}
                catch(Exception e){if(!stopping)event("listener_error",null,fields("type",e.getClass().getSimpleName()));break;}
            }
        },ftp?"lab-ftp":"lab-http");thread.setDaemon(true);thread.start();return server.getLocalPort();
    }
    private static String line(InputStream in,int limit) throws IOException {
        ByteArrayOutputStream b=new ByteArrayOutputStream();for(int i=0;i<limit;i++){int c=in.read();if(c<0)return b.size()==0?null:b.toString("UTF-8");if(c=='\n')return b.toString("UTF-8").replace("\r","");b.write(c);}throw new IOException("Line budget exceeded");
    }
    private static void write(Socket s,String value) throws IOException{s.getOutputStream().write(value.getBytes(StandardCharsets.UTF_8));s.getOutputStream().flush();}
    private void ftp(Socket s) throws IOException {
        write(s,"220 NIDS isolated FTP authentication lab\r\n");String user="";
        for(int i=0;i<4&&!stopping;i++){
            String text=line(s.getInputStream(),256);if(text==null)return;
            if(text.startsWith("USER ")){user=text.substring(5);write(s,"331 Password required\r\n");}
            else if(text.startsWith("PASS ")){
                boolean ok=USER.equals(user)&&PASSWORD.equals(text.substring(5));
                event(ok?"ftp_login_success":"ftp_login_failure",s,fields("dummy_account",true));
                write(s,ok?"230 Dummy account accepted; no file access\r\n":"530 Login incorrect\r\n");return;
            }else if(text.equals("QUIT")){write(s,"221 Goodbye\r\n");return;}
            else{write(s,"502 Command unavailable in isolated lab\r\n");return;}
        }
    }
    private void http(Socket s) throws Exception {
        String request=line(s.getInputStream(),1024);if(request==null)return;
        for(int bytes=request.length();;){String h=line(s.getInputStream(),1024);if(h==null||h.isEmpty())break;bytes+=h.length();if(bytes>4096)throw new IOException("Header budget exceeded");}
        String[] parts=request.split(" ");String path=parts.length>1?parts[1]:"";
        if(path.equals("/bot-start")){
            if(botStarted.compareAndSet(false,true)){Thread t=new Thread(this::bot,"lab-fixed-bot");t.setDaemon(true);t.start();}
            event("bot_trigger",s,Collections.emptyMap());respond(s,202,"{\"started\":true}");return;
        }
        if(!path.equals("/resource")&&!path.equals("/probe")){respond(s,404,"{}");return;}
        boolean held=resource.tryAcquire();
        if(!held){event(path.equals("/probe")?"probe_denied":"resource_denied",s,Collections.emptyMap());respond(s,503,"{\"available\":false,\"dummy_resource\":true}");return;}
        try{
            if(path.equals("/resource")){event("resource_held",s,Collections.emptyMap());Thread.sleep(1000);}
            else event("probe_available",s,Collections.emptyMap());
            respond(s,200,"{\"available\":true,\"dummy_resource\":true}");
        }finally{resource.release();}
    }
    private static void respond(Socket s,int code,String text) throws IOException {
        byte[] data=text.getBytes(StandardCharsets.UTF_8);
        write(s,"HTTP/1.1 "+code+" Lab\r\nContent-Type: application/json\r\nContent-Length: "+data.length+"\r\nConnection: close\r\n\r\n"+text);
    }
    private void bot(){
        for(int i=0;i<12&&!stopping;i++){
            try(Socket s=outboundSockets.createSocket()){
                s.connect(new InetSocketAddress(receiver,RECEIVER),1500);s.setSoTimeout(2000);
                String command=line(s.getInputStream(),32);String reply="PING".equals(command)?"PONG":"STATUS".equals(command)?"LAB-OK":"REJECTED";
                write(s,reply+"\n");event(reply.equals("REJECTED")?"bot_command_rejected":"bot_exchange",s,fields("sequence",i,"command",command==null?"":command,"reply",reply));
            }catch(Exception e){event("bot_error",null,fields("sequence",i,"type",e.getClass().getSimpleName()));}
            try{Thread.sleep(3000);}catch(InterruptedException e){return;}
        }
    }
    public Map<String,Object> status(){return fields("state",stopping?"stopped":"listening","bind",bind,"http_port",httpPort,"ftp_port",ftpPort,"ssh_port",sshPort,"ssh_fingerprint",fingerprint,"expires_ms",until,"version","0.1.0");}
    @Override public synchronized void close(){
        if(stopping)return;stopping=true;for(ServerSocket s:listeners)try{s.close();}catch(IOException ignored){}
        if(ssh!=null)try{ssh.stop(true);}catch(IOException ignored){}workers.shutdownNow();timer.shutdownNow();event("target_stopped",null,Collections.emptyMap());
    }
    public static String json(Object value){
        if(value==null)return "null";if(value instanceof Number||value instanceof Boolean)return value.toString();
        if(value instanceof Map){List<String> parts=new ArrayList<>();for(Object o:((Map<?,?>)value).entrySet()){Map.Entry<?,?> e=(Map.Entry<?,?>)o;parts.add(json(e.getKey().toString())+":"+json(e.getValue()));}return "{"+String.join(",",parts)+"}";}
        String text=value.toString();StringBuilder b=new StringBuilder("\"");for(char c:text.toCharArray()){if(c=='\\'||c=='\"')b.append('\\').append(c);else if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);}return b.append('"').toString();
    }
}
