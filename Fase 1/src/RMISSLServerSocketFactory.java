import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.server.RMIServerSocketFactory;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

public class RMISSLServerSocketFactory implements RMIServerSocketFactory {

	private Config config;

	public ServerSocket createServerSocket(int port) throws IOException {
		try {
			config = new Config();

			String[] confciphersuites = { config.getCiphersuite() };
			String[] confprotocols = { config.getProtocol() };

			SSLServerSocketFactory ssf;

			if (config.getAuthentication().equals("Target") || config.getAuthentication().equals("Mutual")) {

				KeyManagerFactory kmf;
				KeyStore ks;

				char[] passphrase = "hjhjhjhj".toCharArray();
				ks = KeyStore.getInstance("JKS");
				ks.load(new FileInputStream("serverkeystore"), passphrase);

				kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(ks, passphrase);

				SSLContext ctx = SSLContext.getInstance(config.getProtocol());
				ctx.init(kmf.getKeyManagers(), null, null);

				ssf = ctx.getServerSocketFactory();
			} else {
				ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			}

			SSLServerSocket socket = (SSLServerSocket) ssf.createServerSocket(port);
			socket.setEnabledCipherSuites(confciphersuites);
			socket.setEnabledProtocols(confprotocols);

			if (config.getHandshakeStartFlow().equals("Target") && config.getWantAuthentication().equals("True")) {
				socket.setWantClientAuth(true);
			} else {
				socket.setWantClientAuth(false);
			}
			if (config.getHandshakeStartFlow().equals("Target")) {
				socket.setUseClientMode(true);
			} else {
				socket.setUseClientMode(false);
			}
			
//			String [] cs = socket.getEnabledCipherSuites();
//			for (int i = 0; i < cs.length; i++)
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
