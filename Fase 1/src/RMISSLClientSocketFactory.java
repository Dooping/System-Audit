import java.io.FileInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.Socket;
import java.rmi.server.RMIClientSocketFactory;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class RMISSLClientSocketFactory
    implements RMIClientSocketFactory, Serializable {
	
    private Config config;

	private static final long serialVersionUID = 1L;

    public Socket createSocket(String host, int port) throws IOException {
    	try {
			config = new Config();

			String[] confciphersuites = { config.getCiphersuite() };
			String[] confprotocols = { config.getProtocol() };

			SSLSocketFactory ssf;

			if (config.getAuthentication().equals("Client") || config.getAuthentication().equals("Mutual")) {

				KeyManagerFactory kmf;
				KeyStore ks;

				char[] passphrase = "hjhjhjhj".toCharArray();
				ks = KeyStore.getInstance("JKS");
				ks.load(new FileInputStream("serverkeystore"), passphrase);

				kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(ks, passphrase);

				SSLContext ctx = SSLContext.getInstance(config.getProtocol());
				ctx.init(kmf.getKeyManagers(), null, null);

				ssf = ctx.getSocketFactory();
			} else {
				ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
			}

			SSLSocket socket = (SSLSocket) ssf.createSocket(host,port);
//			String[] protocols = socket.getEnabledProtocols();
//			for(int i = 0; i < protocols.length; i++)
//				System.out.println(protocols[i]);
			socket.setEnabledCipherSuites(confciphersuites);
			socket.setEnabledProtocols(confprotocols);
			
			if(config.getHandshakeStartFlow().equals("Client") && config.getWantAuthentication().equals("True")){
				socket.setWantClientAuth(true);
			}else{
				socket.setWantClientAuth(false);
			}
			if (config.getHandshakeStartFlow().equals("Client")) {
				socket.setUseClientMode(true);
			} else {
				socket.setUseClientMode(false);
			}
			
//			String [] cs = socket.getEnabledCipherSuites();
//			for(int i = 0;i<cs.length;i++)
//			System.out.println(cs[i]);
			
			return socket;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
    }

    public int hashCode() {
        return getClass().hashCode();
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        } else if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        return true;
    }
}
