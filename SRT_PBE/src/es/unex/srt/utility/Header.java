package es.unex.srt.utility; /**
 * <p>T�tulo: SRTLab</p>
 * <p>Descripci�n: Pr�cticas de SRT</p>
 * <p>Copyright: Copyright (c) 2014-18</p>
 * <p>Empresa: DISIT de la UEx</p> 
 * @author Lorenzo M. Mart�nez Bravo
 * @version 1.0
 */
import java.io.*;

/**
 * Clase para la gesti�n de la cabecera que se a�ade los mensajes cifrados (ficheros).
 * Permite gestionar los diferentes atributos que se almacenan:
 * --------------------------------------------------------
 * |Mark|Operacion|Algoritmo1|Algoritmo2|Datos ...        |  
 * --------------------------------------------------------
 */
public class Header {
  private final static byte MARK[]= {1,2,3,4,5,6,7,8,9,0};
  private final static byte MARKLENGTH = 10;
  private final static byte HEADERLENGTH = MARKLENGTH+4;  
  /**
   * Operaci�n realizada, codificada segun las definiciones de <code>es.unex.srt.utility.Options</code>
   */
  private byte  operation;
  /**
   * Algoritmos usados codificados segun los valores de <code>es.unex.srt.utility.Options</code>.
   */
  private String  algorithm1,
  				algorithm2;
  /**
   * Datos para las operaciones: salt / mac / hash / signature / ...  
   */
  private byte data[];

  /**
   * Constructor por defecto.    
   */
  public Header() {
    algorithm1 = Options.cipherAlgorithms[0];
    algorithm2 = Options.authenticationAlgorithms[0];
    operation  = Options.OP_NONE;
    data = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, 0x09, 0x0f, 0x0a};	
  }
  /**
   * Constructor. Inicia los atributos con valores suministrados.
   * @param algorithm1 - nombre est�ndar del algoritmo 1
   * @param algorithm2 - nombre est�ndar del algoritmo 2
   * @param data - Datos usados con los algoritmos (salt, ...) 
   */
  public Header(byte operation,String algorithm1, String algorithm2,  byte[] data) {
	 this.operation  = operation;
	 this.algorithm1 = algorithm1;
     this.algorithm2 = algorithm2;
     this.data = data;
  }

  public byte getOperation(){
	    return operation;
  }

  public String getAlgorithm1(){
    return algorithm1;
  }
  
  public String getAlgorithm2(){
	    return algorithm2;
  }
    
  public byte[] getData(){
	    return data;
  }
  
  /**
   * Intenta cargar los datos de una cabecera desde un InputStream ya abierto.   
   * Si tiene exito, los datos quedan en la clase.
   * @param r el InputStream abierto
   * @return true si la carga es correcta, false en otro caso
   */
  public boolean load(InputStream r){
    byte buf[] = new byte[HEADERLENGTH];
    boolean breturn=false;
    try {
      if(r.read(buf,0,HEADERLENGTH)==HEADERLENGTH) {
        byte i=0;
        while((i<MARKLENGTH) && (buf[i]==MARK[i])) i++;
        if (i==MARKLENGTH) {
          operation  = buf[i++];
          algorithm1 = Options.cipherAlgorithms[buf[i++]];
          algorithm2 = Options.authenticationAlgorithms[buf[i++]];
          byte dataLength = buf[i++];
          data = new byte[dataLength];
          if(r.read(data,0,dataLength)==dataLength)                    
        	  breturn = true;
        }
      }
    }
    catch (Exception e) {
      e.printStackTrace();
    }
    return breturn;
  }
  
  /**
   * Intenta guardar la cabecera actual en un OutputStream ya abierto.
   * @param fos el OutputStream abierto
   * @return true si tiene exito, false en otro caso
   */
  public boolean save(OutputStream fos){
    boolean breturn=false;
    try {
      fos.write(MARK);
      fos.write(operation);
      fos.write(Options.search(Options.cipherAlgorithms,algorithm1));
      fos.write(Options.search(Options.authenticationAlgorithms,algorithm2));
      fos.write(data.length);
      fos.write(data, 0, data.length);
      fos.flush();
      breturn = true;
    }
    catch (Exception e) {
    }
    return breturn;
  }

  /**
   * Prueba el funcionamiento de la clase, creando una cabecera, guardandola en un   
   * fichero y recuperandola posteriomente.
   * 
   */
  public void test() {
    try {
        FileOutputStream fos = new FileOutputStream("fileheader.prueba");
        save(fos);
        fos.close();

        Header fh2= new Header();
        FileInputStream fis = new FileInputStream("fileheader.prueba");
        if (fh2.load(fis)){
        	System.out.println("Le�do, Operaci�n: " +fh2.getOperation());
        	System.out.println("Le�do, Algoritmo1: "+fh2.getAlgorithm1());
        	System.out.println("Le�do, Algoritmo2: "+fh2.getAlgorithm2());
        	System.out.print  ("Le�do, Data     : ");
        	for(byte i=0;i<fh2.getData().length;i++)
        		System.out.print(String.format("0x%h ", fh2.getData()[i]));
        }
        else
        	System.out.println("Error en la carga");
        fis.close();
    }
    catch (Exception e) {e.printStackTrace(); };
  }
  
  /**
   * Programa principal para prueba
   * 
   */
//  public static void main(String args[]){
//	  new Header().test();
//  }
  
}//es.unex.srt.utility.Header