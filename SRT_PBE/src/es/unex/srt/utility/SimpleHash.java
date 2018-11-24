package es.unex.srt.utility;

import java.io.*;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Clase para facilitar al máximo las tareas de hashing
 *
 * @author Juan Luis Herrera González y Antonio Narváez López
 * @version 1.0
 */
public class SimpleHash {

    /**
     * Constante para el modo hash
     */
    private static final Integer HASH_MODE = 0;
    /**
     * Constante para el modo verificar
     */
    private static final Integer VERIFY_MODE = 1;

    /**
     * Objeto encargado del hashing
     */
    private MessageDigest hasher;
    /**
     * Tipo de InputStream que nos permite ir hasheando lo que cargamos
     */
    private DigestInputStream hashStream;
    /**
     * OutputStream "limpio" para volver a guardar lo cargado
     */
    private ByteArrayOutputStream auxStream;
    /**
     * Cabecera del fichero con hash
     */
    private Header header;
    /**
     * Algoritmo utilizado
     */
    private String algorithm;
    /**
     * Modo de operación respecto a las constantes definidas
     */
    private Integer operationMode;

    /**
     * Constructor de un SimpleHash para hashing
     *
     * @param buffer    Búfer de entrada con el archivo abierto
     * @param algorithm Algoritmo hash utilizado
     * @param secret    Secreto compartido utilizado
     */
    public SimpleHash(InputStream buffer, String algorithm, String secret) {
        try {
            this.algorithm = algorithm;
            operationMode = HASH_MODE;
            hasher = MessageDigest.getInstance(algorithm);
            hasher.update(secret.getBytes());
            hashStream = new DigestInputStream(buffer, hasher);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("El algoritmo no existe. Usa las constantes de Options, para eso están");
            e.printStackTrace();
        }
    }

    /**
     * Constructor de un SimpleHash para verificación
     *
     * @param buffer Búfer de entrada con el archivo abierto
     * @param secret Secreto compartido utilizado
     */
    public SimpleHash(InputStream buffer, String secret) {
        try {
            header = new Header();
            header.load(buffer);
            operationMode = VERIFY_MODE;
            hasher = MessageDigest.getInstance(header.getAlgorithm2());
            hasher.update(secret.getBytes());
            hashStream = new DigestInputStream(buffer, hasher);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("El algoritmo no existe. Usa las constantes de Options, para eso están");
            e.printStackTrace();
        }
    }

    /**
     * Guarda un archivo con su código hash
     *
     * @param buffer Búfer con el archivo de salida. Se devuelve sin cerrar
     * @return True si se pudo guardar, false si no
     */
    public boolean save(OutputStream buffer) {
        if (Objects.equals(operationMode, HASH_MODE)) {
            try {
                header = new Header(Options.OP_HASH_MAC, Options.cipherAlgorithms[0], algorithm,
                        calculateHash()); //Guardamos el hash como datos del header
                boolean headerSave = header.save(buffer);
                if (!headerSave) {
                    return false;
                }
                buffer.write(auxStream.toByteArray());
                return true;
            } catch (IOException ex) {
                ex.printStackTrace();
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Verifica el código hash del archivo cargado
     *
     * @return True si es válido, false si no
     */
    public boolean verify() {
        if (Objects.equals(operationMode, VERIFY_MODE)) {
            try {
                byte[] calculatedHash = calculateHash();
                byte[] loadedHash = header.getData();
                return Arrays.equals(calculatedHash, loadedHash);
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Método auxiliar que calcula el hash. Utiliza el DigestInputStream, pero lo carga en auxStream
     *
     * @return Código hash calculado
     * @throws IOException IOException interna
     */
    private byte[] calculateHash() throws IOException {
        auxStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1];
        Integer loop_check = hashStream.read(buffer);
        while (loop_check > 0) {
            auxStream.write(buffer);
            loop_check = hashStream.read(buffer);
        }
        return hashStream.getMessageDigest().digest();
    }

    /**
     * Test interno de la clase
     *
     * @throws IOException IOException interna
     */
    private static void test() throws IOException {
        String spike = "Spike";
        //Creamos un archivo de prueba
        OutputStream outputStream = new FileOutputStream("Tank.txt");
        outputStream.write("I think it's time we blow this scene. \n".getBytes());
        outputStream.write("Get everybody and the stuff together \n".getBytes());
        outputStream.write("Okay: 3, 2, 1, let's jam!".getBytes());

        outputStream.flush();
        outputStream.close();

        //Lo cargamos
        InputStream inputStream = new FileInputStream("Tank.txt");
        //Creamos su SimpleHash
        SimpleHash hash = new SimpleHash(inputStream, Options.hashAlgorithms[3], spike);
        //Guardamos su hash
        OutputStream outputStream1 = new FileOutputStream("Tank.hsh");
        hash.save(outputStream1);
        outputStream1.close();
        inputStream.close();

        //Cargamos el archivo hasheado
        InputStream inputStream1 = new FileInputStream("Tank.hsh");
        SimpleHash simpleHash = new SimpleHash(inputStream1, spike);
        if (simpleHash.verify()) {
            System.out.println("Todo funciona guay");
        } else {
            System.out.println("Esto no funciona");
        }
        inputStream1.close();
    }

    /*
    public static void main(String[] args) throws IOException {
        test();
    }
    */


}
