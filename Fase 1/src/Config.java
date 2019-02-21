import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class Config{
	
	String ciphersuite;
	String authentication;
	String wantAuthentication;
	String handshakeStartFlow;
	String protocol;

	public Config() throws FileNotFoundException{
		File config = new File("./config.txt");
		setConfigs(config);
	}

	private void setConfigs(File config) throws FileNotFoundException {
		Scanner reader = new Scanner(config);
		reader.next("Ciphersuite:");
		reader.skip(" ");
		ciphersuite = reader.nextLine();
		reader.next("Authentication:");
		reader.skip(" ");
		authentication = reader.nextLine();
		reader.next("Want-Authentication:");
		reader.skip(" ");
		wantAuthentication = reader.nextLine();
		reader.next("Handshake-Start-Flow:");
		reader.skip(" ");
		handshakeStartFlow = reader.nextLine();
		reader.next("Protocol:");
		reader.skip(" ");
		protocol = reader.nextLine();
		reader.close();
	}

	public String getCiphersuite() {
		return ciphersuite;
	}

	public String getAuthentication() {
		return authentication;
	}

	public String getWantAuthentication() {
		return wantAuthentication;
	}

	public String getHandshakeStartFlow() {
		return handshakeStartFlow;
	}

	public String getProtocol() {
		return protocol;
	}
}
