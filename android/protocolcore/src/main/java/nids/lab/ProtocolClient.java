package nids.lab;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.common.config.keys.KeyUtils;

/** Fixed client supports lab hosts/ports only; no command execution. */
public final class ProtocolClient {
    public static Map<String,Object> login(String kind,String host,int port,boolean correct,String fingerprint) throws Exception {
        return login(kind,host,port,correct,fingerprint,0);
    }
    public static Map<String,Object> login(String kind,String host,int port,boolean correct,String fingerprint,int attempt) throws Exception {
        String password=correct?LabServer.PASSWORD:"nids-lab-wrong-"+attempt;
        long start=System.currentTimeMillis();boolean accepted=false;String error="";
        if(kind.equals("ftp")){
            try(Socket s=new Socket()){
                s.connect(new InetSocketAddress(host,port),2500);s.setSoTimeout(4000);BufferedReader in=new BufferedReader(new InputStreamReader(s.getInputStream(),StandardCharsets.UTF_8));
                if(!in.readLine().startsWith("220"))throw new IOException("FTP banner missing");
                s.getOutputStream().write(("USER "+LabServer.USER+"\r\n").getBytes(StandardCharsets.UTF_8));s.getOutputStream().flush();
                if(!in.readLine().startsWith("331"))throw new IOException("FTP password prompt missing");
                s.getOutputStream().write(("PASS "+password+"\r\n").getBytes(StandardCharsets.UTF_8));s.getOutputStream().flush();
                String response=in.readLine();accepted=response.startsWith("230");if(!accepted&&!response.startsWith("530"))throw new IOException("Unexpected FTP response");
            }
        }else if(kind.equals("ssh")){
            SshClient client=SshClient.setUpDefaultClient();client.setUserAuthFactories(Collections.singletonList(UserAuthPasswordFactory.INSTANCE));client.setServerKeyVerifier((session,address,key)->KeyUtils.getFingerPrint(key).equals(fingerprint));client.start();
            try(ClientSession s=client.connect(LabServer.USER,host,port).verify(5000).getSession()){
                s.addPasswordIdentity(password);
                try{s.auth().verify(5000);accepted=true;}catch(Exception e){error=e.getClass().getSimpleName();if(correct)throw e;}
            }finally{client.stop();}
        }else throw new IllegalArgumentException("Unknown protocol");
        return LabServer.fields("protocol",kind,"accepted",accepted,"expected_success",correct,"start_unix",start/1000.0,"end_unix",System.currentTimeMillis()/1000.0,"error",error);
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=4)throw new IllegalArgumentException("kind host profile fingerprint");
        String kind=args[0],host=args[1],profile=args[2],fp=args[3];
        if(!host.matches("[0-9.]{7,15}")||!InetAddress.getByName(host).isSiteLocalAddress())throw new IllegalArgumentException("Private IPv4 lab target required");
        if(!kind.equals("ftp")&&!kind.equals("ssh"))throw new IllegalArgumentException("Only FTP/SSH lab clients");
        if(!profile.equals("control")&&!profile.equals("guess"))throw new IllegalArgumentException("control or guess only");
        int count=profile.equals("control")?2:32;int port=kind.equals("ftp")?LabServer.FTP:LabServer.SSH;
        for(int i=0;i<count;i++){
            boolean correct=profile.equals("control")&&i==1;
            Map<String,Object> result=login(kind,host,port,correct,fp,i);result.put("index",i);
            System.out.println(LabServer.json(result));System.out.flush();Thread.sleep(profile.equals("control")?1000:200);
        }
    }
}
