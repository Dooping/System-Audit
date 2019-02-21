import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.io.*;

import javax.net.SocketFactory;
import javax.net.ssl.*;

public class SSLClient {

    public static void main(String[] args) {
    	
    	List<String> protocols = loadFile("./weak_protocols.cfg");
    	List<String> insecure = loadFile("./insecure_ciphersuites.cfg");
    	List<String> weak = loadFile("./weak_ciphersuites.cfg");


        SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
        System.out.println("Testing Protocols:");
        for(String p : protocols)
        	try {
        		System.out.print(p);
        		SSLSocket c = (SSLSocket) f.createSocket(args[0], 443);
        		String[] protocolString = { p };
        		c.setEnabledProtocols(protocolString);
        		c.startHandshake();
        		c.close();
        		System.out.println(" - Supported");
        	} catch (IOException e) {
        		System.out.println(" - Not Supported");
        	} catch (IllegalArgumentException e){
        		System.out.println(" - Cannot test");
        	}
        
        System.out.println();
        System.out.println("Insecure ciphersuits:");
        for(String cypher : insecure)
        	testCiphersuit(cypher, f, args[0]);
        
        System.out.println();
        System.out.println("Weak ciphersuits:");
        for(String cypher : weak)
        	testCiphersuit(cypher, f, args[0]);
    }
    
    /**
     * Testa uma ciphersuit
     * @param cipher - ciphersuit a testar
     * @param f - SocketFactory a partir da qual se vai fazer a ligacao
     * @param address - endereco no qual a ciphersuit vai ser testada
     */
    private static void testCiphersuit(String cipher, SocketFactory f, String address){
    	try {
    		System.out.print(cipher);
    		SSLSocket c = (SSLSocket) f.createSocket(address, 443);
    		String[] cypherString = { cipher };
    		c.setEnabledCipherSuites(cypherString);
    		c.startHandshake();
    		System.out.println(" - Supported");
    		System.out.println("Testing certificates:");
    		Certificate[] certificates = c.getSession().getPeerCertificates();
    		for (Certificate cert : certificates) {
                //System.out.print(cert);
                if(cert instanceof X509Certificate) {
                	System.out.print(((X509Certificate) cert).getIssuerDN().getName()+" - ");
                    try {
                        ( (X509Certificate) cert).checkValidity();
                        System.out.println("active for current date");
                    } catch(CertificateExpiredException cee) {
                        System.out.println("expired");
                    } catch (CertificateNotYetValidException e) {
						System.out.println("not yet valid");
					}
                }
            }
    		c.close();
    	} catch (IOException e) {
    		System.out.println(" - Not Supported");
    	} catch (IllegalArgumentException e){
    		System.out.println(" - Cannot test");
    	}
    }
    
    /**
     * Funcao que vai buscar uma lista de strings a um ficheiro
     * @param file - ficheiro com a lista
     * @return - lista de strings
     */
    private static List<String> loadFile(String file){
    	List<String> list = new LinkedList<>();
    	try {
			Scanner reader = new Scanner(new File(file));
			while(reader.hasNext())
				list.add(reader.next());
			reader.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
    	return list;
    }
}