package nids.lab;

import java.net.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/** PC-loopback test that an unapproved emulator command cannot execute. */
public final class BotSafetySmoke {
    public static void main(String[] args) throws Exception {
        List<Map<String,Object>> events=new CopyOnWriteArrayList<>();
        ExecutorService pool=Executors.newSingleThreadExecutor();
        try(ServerSocket receiver=new ServerSocket(LabServer.RECEIVER,4,InetAddress.getByName("127.0.0.1"));
            LabServer lab=new LabServer("127.0.0.1",new HashSet<>(Collections.singletonList("127.0.0.1")),"127.0.0.1",events::add)){
            receiver.setSoTimeout(4000);lab.start(0,0,0);
            Future<String> reply=pool.submit(()->{try(Socket s=receiver.accept()){
                s.setSoTimeout(3000);s.getOutputStream().write("UNAPPROVED-COMMAND\n".getBytes("US-ASCII"));s.getOutputStream().flush();
                return new BufferedReader(new InputStreamReader(s.getInputStream(),"US-ASCII")).readLine();
            }});
            HttpURLConnection c=(HttpURLConnection)new URL("http://127.0.0.1:"+lab.status().get("http_port")+"/bot-start").openConnection();
            c.setReadTimeout(3000);if(c.getResponseCode()!=202)throw new AssertionError("Emulator trigger failed");c.disconnect();
            if(!"REJECTED".equals(reply.get(5,TimeUnit.SECONDS)))throw new AssertionError("Unknown command not rejected");
            long until=System.currentTimeMillis()+1000;while(events.stream().noneMatch(r->"bot_command_rejected".equals(r.get("event")))&&System.currentTimeMillis()<until)Thread.sleep(10);
            if(events.stream().noneMatch(r->"bot_command_rejected".equals(r.get("event"))))throw new AssertionError("Independent rejection event missing");
            System.out.println("{\"passed\":true,\"scope\":\"PC loopback only\",\"unapproved_command_rejected\":true,\"phone_actions\":0}");
        }finally{pool.shutdownNow();}
    }
}
