import java.io.File;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.MessageDigest;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;

public class AuditClient {

    private static final int PORT = 2019;

    public static void main(String args[]) {
    	if(args.length < 8){
    		System.err.println("Correct format: -target <host> -nonce <nonce> -checkdir/checkentry/checkdirall <path> -hash <hashfunction>");
    	}
    	
    	String host = "localhost", path = "", hashf = "";
    	long nounce = System.currentTimeMillis();
    	
    	for(int i = 0; i<7;i++)
    		switch (args[i]){
    			case "-target":
    				host = args[++i];
    				break;
    			case "-nonce":
    				nounce = Long.parseLong(args[++i]);
    				break;
    			case "-hash":
    				hashf = args[++i];
    				break;
    		}
    		
        try {

        	RMISSLClientSocketFactory clientFactory = new RMISSLClientSocketFactory();
//        	Registry registry = LocateRegistry.getRegistry(
//							   InetAddress.getLocalHost().getHostName(), PORT,
//							   clientFactory);
        	Registry registry = LocateRegistry.getRegistry(
					   host, PORT,
					   clientFactory);

            Audit obj = (Audit) registry.lookup("Audit");

            System.out.println("Connected");
//          System.out.println(clientFactory.socket.getSession());

            //long nounce = System.currentTimeMillis();
            
            File auditFile = new File("./auditFile.txt");
            Scanner reader = new Scanner(auditFile);
            
            String s, aux;
            List<String> output = new LinkedList<>();
            List<String> files = new LinkedList<>();
            
			MessageDigest hash = MessageDigest.getInstance(hashf,"BC");

            while (reader.hasNext())
			{
            	aux = reader.nextLine();
            	files.add(aux);
				s = aux+" "+nounce; 
				hash.update(s.getBytes());

				output.add(Utils.toHex(hash.digest(s.getBytes())));
			}
            reader.close();
            
            List<String> message = null;
            for(int i = 0; i<7;i++)
        		switch (args[i]){
        			case "-checkdir":
        			case "-checkentry":
        				path = args[++i];
        	            message = obj.audit(path,hashf, nounce);
        				break;
        			case "-checkdirall":
        				path = args[++i];
        				message = obj.auditRecursive(path,hashf, nounce);
        				break;
        		}
            
            if(output.size() != message.size())
            	System.out.println("Number of files is different");
            for(int i = 0; i < output.size(); i++){
            	System.out.print(files.get(i));
            	if(!output.get(i).equals(message.get(i)))
            		System.out.println(" conflict detected");
            	else
            		System.out.println(" OK");
            }
            
        } catch (Exception e) {
            System.out.println("AuditClient exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
