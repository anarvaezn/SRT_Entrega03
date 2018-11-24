package es.unex.srt.utility;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Clase para facilitar al máximo las tareas de MAC
 */
public class SimpleMAC {
    /**
     * Constante para el modo MAC
     */
    private static final Integer MAC_MODE = 0;
    /**
     * Constante para el modo verificar
     */
    private static final Integer VERIFY_MODE = 1;
    /**
     * Sal predefinida
     */
    private static final byte[] sal = {0x00, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x77};
    /**
     * Objeto encargado de calcular el MAC
     */
    private Mac mac;
    /**
     * OutputStream "limpio" para volver a guardar lo cargado
     */
    private ByteArrayOutputStream auxStream;
    /**
     * Cabecera del fichero con MAC
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
     * InputStream del archivo a leer
     */
    private InputStream openFile;

    /**
     * Constructor de un SimpleMAC para cálculo de MAC
     *
     * @param stream         Búfer de entrada con el archivo abierto
     * @param algorithm      Algoritmo MAC/HMAC utilizado
     * @param secret         Secreto compartido utilizado
     * @param iterationCount Iteraciones a realizar
     */
    public SimpleMAC(InputStream stream, String algorithm, String secret, Integer iterationCount) {
        try {
            this.algorithm = algorithm;
            openFile = stream;
            operationMode = MAC_MODE;
            mac = Mac.getInstance(algorithm);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec keySpec = new PBEKeySpec(secret.toCharArray(), sal, iterationCount, mac.getMacLength());
            SecretKey key = secretKeyFactory.generateSecret(keySpec);
            mac.init(key);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("El algoritmo no existe. Usa las constantes de Options, para eso están");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("Especificaciones de la clave no válidas");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("Clave no válida");
            e.printStackTrace();
        }
    }

    /**
     * Constructor de un SimpleMAC para verificación
     *
     * @param stream         Búfer de entrada con el archivo abierto
     * @param secret         Secreto compartido utilizado
     * @param iterationCount Iteraciones a realizar
     */
    public SimpleMAC(InputStream stream, String secret, Integer iterationCount) {
        try {
            header = new Header();
            header.load(stream);
            openFile = stream;
            operationMode = VERIFY_MODE;
            algorithm = header.getAlgorithm2();
            mac = Mac.getInstance(algorithm);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec keySpec = new PBEKeySpec(secret.toCharArray(), sal, iterationCount, mac.getMacLength());
            SecretKey key = secretKeyFactory.generateSecret(keySpec);
            mac.init(key);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("El algoritmo no existe. Usa las constantes de Options, para eso están");
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.err.println("Especificaciones de la clave no válidas");
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            System.err.println("Clave no válida");
            e.printStackTrace();
        }
    }

    /**
     * Guarda un archivo con su código MAC
     *
     * @param buffer Búfer con el archivo de salida. Se devuelve sin cerrar
     * @return True si se pudo guardar, false si no
     */
    public boolean save(OutputStream buffer) {
        if (Objects.equals(operationMode, MAC_MODE)) {
            try {
                header = new Header(Options.OP_HASH_MAC, Options.cipherAlgorithms[0], algorithm, calculateMac());
                boolean headerSave = header.save(buffer);
                if (!headerSave) {
                    return false;
                }
                buffer.write(auxStream.toByteArray());
                return true;
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Verifica el código MAC del archivo cargado
     *
     * @return True si es válido, false si no
     */
    public boolean verify() {
        if (Objects.equals(operationMode, VERIFY_MODE)) {
            try {
                byte[] calculatedMac = calculateMac();
                byte[] loadedMac = header.getData();
                return Arrays.equals(calculatedMac, loadedMac);
            } catch (IOException e) {
                e.printStackTrace();
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Método auxiliar que calcula el MAC. Utiliza el InputStream, pero lo carga en auxStream
     *
     * @return Código MAC calculado
     * @throws IOException IOException interna
     */
    private byte[] calculateMac() throws IOException {
        auxStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1];
        Integer loop_check = openFile.read(buffer);
        while (loop_check > 0) {
            auxStream.write(buffer);
            mac.update(buffer);
            loop_check = openFile.read(buffer);
        }
        return mac.doFinal();
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
        //Creamos su SimpleMAC
        SimpleMAC mac = new SimpleMAC(inputStream, Options.macAlgorithms[2], spike, 1024);
        //Guardamos su hash
        OutputStream outputStream1 = new FileOutputStream("Tank.hsh");
        mac.save(outputStream1);
        outputStream1.close();
        inputStream.close();

        //Cargamos el archivo hasheado
        InputStream inputStream1 = new FileInputStream("Tank.hsh");
        SimpleMAC simpleMAC = new SimpleMAC(inputStream1, spike, 1024);
        if (simpleMAC.verify()) {
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
