package es.unex.srt.utility;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Clase para facilitar al máximo las tareas de cifrado y descifrado
 *
 * @author Juan Luis Herrera González y Antonio Narváez López
 * @version 1.0
 */
public class SimpleCipher {

    /**
     * Cifrador
     */
    private Cipher c;
    /**
     * Clave PBE
     */
    private PBEKeySpec pbeKeySpec;
    /**
     * Parámetros PBE
     */
    private PBEParameterSpec pbeParameterSpec;
    /**
     * Fábrica de claves secretas
     */
    private SecretKeyFactory keyFactory;
    /**
     * Clave secreta
     */
    private SecretKey secretKey;
    /**
     * Cabecera del fichero a cifrar/descifrar
     */
    private Header header;
    /**
     * InputStream del archivo cargado
     */
    private InputStream loaded_file;
    /**
     * Modo de operación. True implica cifrado, False implica descifrado.
     */
    private boolean operationMode;

    /**
     * Constructor de un SimpleCipher para descifrado
     *
     * @param in_buff        Búfer con el fichero cifrado abierto
     * @param password       Contraseña de usuario para PBE
     * @param iterationCount Iteraciones a realizar
     */
    public SimpleCipher(InputStream in_buff, String password, Integer iterationCount) {
        try {
            operationMode=false;
            loaded_file = in_buff;
            header=new Header();
            header.load(in_buff);
            pbeKeySpec = new PBEKeySpec(password.toCharArray());
            pbeParameterSpec = new PBEParameterSpec(header.getData(), iterationCount);
            keyFactory = SecretKeyFactory.getInstance(header.getAlgorithm1());
            secretKey = keyFactory.generateSecret(pbeKeySpec);
            c = Cipher.getInstance(header.getAlgorithm1());
            c.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("El algoritmo no existe. Usa las constantes de Options, para eso están");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.err.println("El padding ha provocado un error");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("La SecretKeyFactory no es capaz de manejar el KeySpec");
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Los parámetros del algoritmo no son válidos");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("La clave no es válida");
            e.printStackTrace();
        }
    }

	/**
     * Constructor de un SimpleCipher para cifrado
     *
     * @param in_buff        Búfer con el fichero en claro abierto
     * @param password       Contraseña de usuario para PBE
     * @param iterationCount Iteraciones a realizar
     */
    public SimpleCipher(InputStream in_buff, String algorithm, String password, Integer iterationCount) {
        try {
            operationMode=true;
            loaded_file = in_buff;
            SecureRandom RNG = new SecureRandom(); //La sal se genera aleatoriamente
            byte[] sal = new byte[8];
            RNG.nextBytes(sal);
            header=new Header(Options.OP_SYMMETRIC_CIPHER, algorithm, Options.authenticationAlgorithms[0], sal);
            pbeKeySpec = new PBEKeySpec(password.toCharArray());
            pbeParameterSpec = new PBEParameterSpec(header.getData(), iterationCount);
            keyFactory = SecretKeyFactory.getInstance(header.getAlgorithm1());
            secretKey = keyFactory.generateSecret(pbeKeySpec);
            c = Cipher.getInstance(header.getAlgorithm1());
            c.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("El algoritmo no existe. Usa las constantes de Options, para eso están");
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            System.err.println("El padding ha provocado un error");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("La SecretKeyFactory no es capaz de manejar el KeySpec");
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Los parámetros del algoritmo no son válidos");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("La clave no es válida");
            e.printStackTrace();
        }
    }

    /**
     * Método que guarda el archivo cifrado/descifrado
     * @param out_buff Búfer con el archivo de salida. Se devuelve sin cerrar
     * @return True si se pudo guardar, false si no
     */
    public boolean save(OutputStream out_buff) {
        try {
            //Guardando la cabecera sin cifrar si estamos cifrando
            //Si estamos descifrando, debe quedar en claro sin cabecera alguna
            if(operationMode) {
                boolean headerSave = header.save(out_buff);
                if (!headerSave) {
                    return false;
                }
            }
            //Guardando el resto
            CipherOutputStream cout_buff = new CipherOutputStream(out_buff, c);
            byte[] buffer = new byte[1];
            Integer loop_check = loaded_file.read(buffer);
            while (loop_check > 0) {
                cout_buff.write(buffer);
                loop_check = loaded_file.read(buffer);
            }
            cout_buff.close();
            return true;
        } catch (IOException ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
}
