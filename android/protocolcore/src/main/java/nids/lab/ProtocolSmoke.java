package nids.lab;

import java.net.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

/** Real protocol integration on PC loopback only; no device or external target. */
public final class ProtocolSmoke {
    public static void main(String[] args) throws Exception {
        List<Map<String,Object>> events=new CopyOnWriteArrayList<>();
        try(LabServer server=new LabServer("127.0.0.1",new HashSet<>(Collections.singletonList("127.0.0.1")),"127.0.0.1",events::add)){
            server.start(0,0,0);Map<String,Object> status=server.status();String fp=(String)status.get("ssh_fingerprint");
            for(String kind:Arrays.asList("ftp","ssh")){
                int port=((Number)status.get(kind+"_port")).intValue();
                if((Boolean)ProtocolClient.login(kind,"127.0.0.1",port,false,fp).get("accepted"))throw new AssertionError("Wrong dummy password accepted");
                if(!(Boolean)ProtocolClient.login(kind,"127.0.0.1",port,true,fp).get("accepted"))throw new AssertionError("Valid dummy login rejected");
            }
            int port=((Number)status.get("http_port")).intValue();
            ExecutorService pool=Executors.newFixedThreadPool(6);List<Future<Integer>> calls=new ArrayList<>();
            for(int i=0;i<6;i++)calls.add(pool.submit(()->http(port,"/resource")));
            int denied=0,ok=0;for(Future<Integer> f:calls){int code=f.get();if(code==503)denied++;else if(code==200)ok++;else throw new AssertionError(code);}
            pool.shutdown();if(denied==0||ok!=2||http(port,"/probe")!=200)throw new AssertionError("Bounded capacity/availability/recovery failed");
            if(events.stream().filter(r->"ftp_login_failure".equals(r.get("event"))).count()!=1||events.stream().filter(r->"ssh_login_failure".equals(r.get("event"))).count()!=1)throw new AssertionError("Independent auth effects missing");
            System.out.println(LabServer.json(LabServer.fields("passed",true,"scope","PC loopback only; no phone attacks","real_ftp_password_auth",true,"real_ssh_password_auth",true,"dummy_resource_denials",denied,"resource_recovery",true,"shell_or_file_access",false)));
        }
    }
    private static int http(int port,String path)throws Exception{
        HttpURLConnection c=(HttpURLConnection)new URL("http://127.0.0.1:"+port+path).openConnection();c.setConnectTimeout(2000);c.setReadTimeout(4000);try{return c.getResponseCode();}finally{c.disconnect();}
    }
}
