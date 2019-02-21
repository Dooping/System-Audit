import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class AuditAgent extends UnicastRemoteObject implements Audit{
	
	private static final int PORT = 2019;

	public AuditAgent() throws Exception {
		super(PORT,
				new RMISSLClientSocketFactory(),
				new RMISSLServerSocketFactory());
	}

	public static void main(String args[]) {

		try {

			Registry registry = LocateRegistry.createRegistry(PORT,
					new RMISSLClientSocketFactory(),
					new RMISSLServerSocketFactory());

			AuditAgent obj = new AuditAgent();

			registry.bind("Audit", obj);

			System.out.println("AuditAgent bound in registry");
		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}
	}

	/*@Override
	public String audit(String dir, String hashFunction, long nounce) throws RemoteException {

		String s;
		String output = "";
		Process process;
		String cmd="ls -l " + dir;

		try {
			MessageDigest hash = MessageDigest.getInstance(hashFunction,"BC");
			process = Runtime.getRuntime().exec(cmd);
			BufferedReader br = new BufferedReader(
					new InputStreamReader(process.getInputStream()));
			while ((s = br.readLine()) != null)
			{
				s += " "+nounce; 
				hash.update(s.getBytes());

				output += Utils.toHex(hash.digest(s.getBytes()))+"\n";
			}
		} catch (Exception e){
			e.printStackTrace();
		}
		return output;
	}*/
	
	@Override
	public List<String> audit(String dir, String hashFunction, long nounce) throws RemoteException {

		File dirr = new File(dir);
		String[] listFiles = dirr.list();
		List<String> output = new LinkedList<>();
		
		for (String a : listFiles){

			Path path = Paths.get(dir + "/" + a);
			Set<PosixFilePermission> set;
			try {
				set = Files.getPosixFilePermissions(path);
				BasicFileAttributes attr =
					    Files.readAttributes(path, BasicFileAttributes.class);
					String line = path + " " + PosixFilePermissions.toString(set) + " " + attr.creationTime()
						+ " " + attr.lastModifiedTime() + " " + attr.size() + " " + nounce;
					MessageDigest hash = MessageDigest.getInstance(hashFunction,"BC");
					hash.update(line.getBytes());
					System.out.println(line);

					output.add(Utils.toHex(hash.digest(line.getBytes())));
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			}
		}
		return output;
	}
	
	/*@Override
	public String auditRecursive(String dir, String hashFunction, long nounce) throws RemoteException {

		String s;
		String output = "";
		Process process;
		String cmd="ls -l -R " + dir;

		try {
			MessageDigest hash = MessageDigest.getInstance(hashFunction,"BC");
			process = Runtime.getRuntime().exec(cmd);
			BufferedReader br = new BufferedReader(
					new InputStreamReader(process.getInputStream()));
			while ((s = br.readLine()) != null)
			{
				s += " "+nounce; 
				hash.update(s.getBytes());

				output += Utils.toHex(hash.digest(s.getBytes()))+"\n";
			}
		} catch (Exception e){
			e.printStackTrace();
		}
		return output;
	}*/
	
	@Override
	public List<String> auditRecursive(String dir, String hashFunction, long nounce) throws RemoteException {

		File dirr = new File(dir);
		String[] listFiles = dirr.list();
		List<String> output = new LinkedList<>();
		
		for (String a : listFiles){
			File test = new File(dirr,a);
			if(test.isDirectory())
				output.addAll(auditRecursive(test.getPath(), hashFunction, nounce));

			Path path = test.toPath();
			Set<PosixFilePermission> set;
			try {
				set = Files.getPosixFilePermissions(path);
				BasicFileAttributes attr =
					    Files.readAttributes(path, BasicFileAttributes.class);
					String line = path + " " + PosixFilePermissions.toString(set) + " " + attr.creationTime()
						+ " " + attr.lastModifiedTime() + " " + attr.size() + " " + nounce;
					MessageDigest hash = MessageDigest.getInstance(hashFunction,"BC");
					hash.update(line.getBytes());
					System.out.println(path + " " + PosixFilePermissions.toString(set) + " " + attr.creationTime()
					+ " " + attr.lastModifiedTime() + " " + attr.size());

					output.add(Utils.toHex(hash.digest(line.getBytes())));
			} catch (IOException e) {
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				e.printStackTrace();
			}
		}
		return output;
	}
}
