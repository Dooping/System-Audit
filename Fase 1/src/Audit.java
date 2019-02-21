import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface Audit extends Remote {
    
	/**
	 * Metodo para auditorar uma directoria e todas as directorias subjacentes
	 * @param dir - directoria alvo
	 * @param hashFunction - funcao de hash
	 * @param nounce - valor a ser usado na funcao de hash
	 * @return - lista de todas as verificacoes
	 * @throws RemoteException
	 */
    List<String> auditRecursive(String dir, String hashFunction, long nounce) throws RemoteException;
    
    /**
     * Metodo chamado para auditorar uma directoria ou um ficheiro
     * @param dir - directoria alvo
     * @param hashFunction - funcao de hash
     * @param nounce - valor a ser usado na funcao de hash
     * @return - lista de todas as verificacoes
     * @throws RemoteException
     */
    List<String> audit(String dir, String hashFunction, long nounce) throws RemoteException;
}