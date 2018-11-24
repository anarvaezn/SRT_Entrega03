package es.unex.srt.main;

import es.unex.srt.utility.Options;
import es.unex.srt.utility.SimpleCipher;
import es.unex.srt.utility.SimpleHash;
import es.unex.srt.utility.SimpleMAC;

import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.io.*;
import java.util.Scanner;

import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.WindowConstants;

/**
 * Clase que controla la ejecuci贸n de la funci贸n principal (main) en modo
 * comando
 *
 * @author Juan Luis Herrera y Antonio Narv谩ez L贸pez
 * @version 1.0
 */
public class MainClass {

	/**
	 * Constante del nombre del modo cifrado
	 */
	private static final String CIPH_MODE = "Cif";
	/**
	 * Constante del nombre del modo descifrado
	 */
	private static final String DEC_MODE = "Dec";
	/**
	 * Contador de iteraciones
	 */
	private static final Integer IT_COUNT = 1024;

	/**
	 * Almacena los textos que van saliendo por pantalla
	 */
	private String informacion = "";

	/**
	 * Modo de uso del usuario
	 */
	private String mode = "PBEWithMD5AndDES";

	/**
	 * Direcci髇 archivo origen para el cifrado
	 */
	private String dirCifrado = "";

	/**
	 * Direcci髇 archivo destino para el descifrado
	 */
	private String dirDestCifrado = "";

	/**
	 * Contrase馻 introducida por el usuario
	 */
	private String passwordUser = "";

	/**
	 * Algoritmo Hash/Hmac
	 */
	private String HashHmac = "MD2";
	
	/**
	 * M閠odo que realiza el cifrado en el programa principal
	 */
	private void cifrar() {
		// String alg = args[1]; //Tomamos el algoritmo pedido
		boolean valid = false;
		for (int i = 1; i < Options.cipherAlgorithms.length; i++) {
			valid = valid || Options.cipherAlgorithms[i].equals(mode); // Lo buscamos entre los conocidos
		}
		if (!valid) { // Si no estaba, mostramos los algoritmos v醠idos
			informacion = informacion + "Algoritmos v醠idos: \n";
			for (int i = 1; i < Options.cipherAlgorithms.length; i++) {
				informacion = informacion + Options.cipherAlgorithms[i] + "\n";
			}
			System.exit(-1);
		} else {
			try {
				InputStream in = new FileInputStream(dirCifrado); // Cargamos el archivo
				SimpleCipher cipher = new SimpleCipher(in, mode, passwordUser, IT_COUNT);
				OutputStream out = new FileOutputStream(dirDestCifrado + ".cph");
				cipher.save(out); // Ciframos el archivo con SimpleCipher
				informacion = informacion + "rchivo cifrado con 閤ito! \n" + "B鷖calo como " + dirDestCifrado + ".cph \n"; 
				// Fin de la ejecuci髇
			} catch (FileNotFoundException e) {
				System.err.println("Archivo no encontrado");
				e.printStackTrace();
				System.exit(-1);
			}
		}
	}
	
	public void cifrarHash() {
		// String alg = args[1]; //Tomamos el algoritmo pedido
		
		boolean esMac = false;
		boolean esHash = false;
		for (int i = 0; i < Options.hashAlgorithms.length; i++) {
			esHash = esHash || Options.hashAlgorithms[i].equals(HashHmac); // Lo buscamos entre los conocidos
		}
		
		for (int i = 0; i < Options.macAlgorithms.length; i++) {
			esMac = esMac || Options.macAlgorithms[i].equals(HashHmac); // Lo buscamos entre los conocidos
		}
		
		if(esMac) {	
			try {
				InputStream in = new FileInputStream(dirCifrado); // Cargamos el archivo
				SimpleMAC cipher = new SimpleMAC(in, HashHmac, passwordUser, IT_COUNT);
				OutputStream out = new FileOutputStream(dirDestCifrado + ".cph");
				cipher.save(out); // Ciframos el archivo con SimpleMAC
				informacion = informacion + "rchivo cifrado con 閤ito con Algoritmo MAc"+ HashHmac +  "\n" + "B鷖calo como " + dirDestCifrado + ".cph \n"; 
				// Fin de la ejecuci髇
			} catch (FileNotFoundException e) {
				System.err.println("Archivo no encontrado");
				e.printStackTrace();
				System.exit(-1);
			}
		}
		
		if(esHash) {	
			try {
				InputStream in = new FileInputStream(dirCifrado); // Cargamos el archivo
				SimpleHash cipher = new SimpleHash(in, HashHmac, passwordUser);
				OutputStream out = new FileOutputStream(dirDestCifrado + ".cph");
				cipher.save(out); // Ciframos el archivo con SimpleHash
				informacion = informacion + "rchivo cifrado con 閤ito con Algortimo Hash " + HashHmac + "\n" + "B鷖calo como " + dirDestCifrado + ".cph \n"; 
				// Fin de la ejecuci髇
			} catch (FileNotFoundException e) {
				System.err.println("Archivo no encontrado");
				e.printStackTrace();
				System.exit(-1);
			}
		}
		
	}
	
	public void verificarHash() throws FileNotFoundException {
		InputStream inputStream1;
		try {
			
			boolean esMac = false;
			boolean esHash = false;
			for (int i = 0; i < Options.hashAlgorithms.length; i++) {
				esHash = esHash || Options.hashAlgorithms[i].equals(HashHmac); // Lo buscamos entre los conocidos
			}
			
			for (int i = 0; i < Options.macAlgorithms.length; i++) {
				esMac = esMac || Options.macAlgorithms[i].equals(HashHmac); // Lo buscamos entre los conocidos
			}
			
			inputStream1 = new FileInputStream(dirCifrado);
			if(esHash) {
			SimpleHash simpleHash = new SimpleHash(inputStream1, passwordUser);
			
			if (simpleHash.verify()) {
				informacion = informacion + "Todo funciona guay \n";
			} else {
				informacion = informacion + "Esto no funciona \n";
			}
			}
			
			if(esMac) {
				SimpleMAC simpleMAC = new SimpleMAC(inputStream1, passwordUser, IT_COUNT);
				
				if (simpleMAC.verify()) {
					informacion = informacion + "Todo funciona guay \n";
				} else {
					informacion = informacion + "Esto no funciona \n";
				}
				
			}
			inputStream1.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	/**
	 * M閠odo que realiza el descifrado en el programa principal
	 */
	public void descifrar() {
		try {
			InputStream in = new FileInputStream(dirCifrado); // Cargamos el archivo
			SimpleCipher cipher = new SimpleCipher(in, passwordUser, IT_COUNT);
			OutputStream out = new FileOutputStream(dirDestCifrado + ".clr");
			cipher.save(out); // Desciframos el archivo con SimpleCipher
			informacion = informacion +"rchivo descifrado con 閤ito! \n" + "B鷖calo como " + dirDestCifrado + ".clr \n";
			
		} catch (

		FileNotFoundException e) {
			System.err.println("Archivo no encontrado");
			e.printStackTrace();
			System.exit(-1);
		}
	}

	/**
	 * Ejecuci髇 del programa en modo ventanas.
	 */
	public void ejecucion() {

		JFrame ventana = new JFrame("Pr醕tica 3. SRT");
		ventana.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		ventana.setSize(700, 400);

		JScrollPane scrPane = new JScrollPane();
		ventana.add(scrPane);

		JTextArea texto = new JTextArea();
		ventana.add(texto);
		texto.setLineWrap(true);
		informacion = informacion + "Programa Iniciado \n";
		texto.setText(informacion);
		ventana.add(texto);

		JMenuBar menuBar = new JMenuBar();
		JMenu menu = new JMenu("Fichero");
		menuBar.add(menu);
		JMenuItem item = new JMenuItem("Cifrar");
		item.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				informacion = informacion + "Iniciando cifrado ... \n";
				texto.setText(informacion);
				ventana.add(texto);
				JFileChooser fc = new JFileChooser();
				fc.setDialogTitle("Fichero a cifrar");
				informacion = informacion + "Seleccionando fichero a cifrar ...\n ";
				texto.setText(informacion);
				int seleccion = fc.showOpenDialog(fc);
				if (seleccion == JFileChooser.APPROVE_OPTION) {

					// Pedimos al usuario el archivo que vamos a cifrar
					File archivoElegido = fc.getSelectedFile();
					String name = archivoElegido.getAbsolutePath();
					informacion = informacion + "Archivo a cifrar" + name + "\n";
					texto.setText(informacion);
					dirCifrado = name;

					Boolean Bandera = false;

					// Pedimos al usuario la contrase馻
					while (!Bandera) {
						String contrasenia01 = JOptionPane.showInputDialog("Introduce la contrase馻 de cifrado");
						String contrasenia02 = JOptionPane
								.showInputDialog("Introduce la contrase馻 de cifrado de nuevo");
						if (contrasenia01.equals(contrasenia02)) {
							Bandera = true;
						} else {
							passwordUser = contrasenia01;
							informacion = informacion + " Debe introducir la misma contrase馻 de cifrado en ambos casos";
							texto.setText(informacion);
						}
					}

					// Pedimos al usuario el directorio donde queremos guardar el fichero cifrado
					JFileChooser jfc = new JFileChooser();
					jfc.showSaveDialog(jfc);
					informacion = informacion + "Seleccione directorio a guardar el fichero \n";
					texto.setText(informacion);
					File Guardamos = jfc.getSelectedFile();
					informacion = informacion + "Guardamos el fichero con el nombre :" + Guardamos.getName() + "\n";
					texto.setText(informacion);
					dirDestCifrado = Guardamos.getAbsolutePath();

					// Llamamos al m閠odo cifrar una vez que tenemos todos los datos necesarios del
					// usuario
					cifrar();

					texto.setText(informacion);
				}
			}
		});
		menu.add(item);
		
		JMenuItem itemN1 = new JMenuItem("Proteger con hash");
		itemN1.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				informacion = informacion + "Iniciando cifrado con hash ... \n";
				texto.setText(informacion);
				ventana.add(texto);
				JFileChooser fc = new JFileChooser();
				fc.setDialogTitle("Fichero a cifrar");
				informacion = informacion + "Seleccionando fichero a cifrar con hash ...\n ";
				texto.setText(informacion);
				int seleccion = fc.showOpenDialog(fc);
				if (seleccion == JFileChooser.APPROVE_OPTION) {

					// Pedimos al usuario el archivo que vamos a cifrar
					File archivoElegido = fc.getSelectedFile();
					String name = archivoElegido.getAbsolutePath();
					informacion = informacion + "Archivo a cifrar con hash" + name + "\n";
					texto.setText(informacion);
					dirCifrado = name;
					Boolean Bandera = false;

					// Pedimos al usuario la contrase馻
					while (!Bandera) {
						String contrasenia01 = JOptionPane.showInputDialog("Introduce la contrase馻 de cifrado");
						String contrasenia02 = JOptionPane
								.showInputDialog("Introduce la contrase馻 de cifrado de nuevo");
						if (contrasenia01.equals(contrasenia02)) {
							Bandera = true;
						} else {
							passwordUser = contrasenia01;
							informacion = informacion
									+ " Debe introducir la misma contrase馻 de cifrado en ambos casos";
							texto.setText(informacion);
						}
					}

					// Pedimos al usuario el directorio donde queremos guardar el fichero cifrado
					JFileChooser jfc = new JFileChooser();
					jfc.showSaveDialog(jfc);
					informacion = informacion + "Seleccione directorio a guardar el fichero \n";
					texto.setText(informacion);
					File Guardamos = jfc.getSelectedFile();
					informacion = informacion + "Guardamos el fichero con el nombre :" + Guardamos.getName() + "\n";
					texto.setText(informacion);
					dirDestCifrado = Guardamos.getAbsolutePath();

					// Llamamos al m閠odo cifrar una vez que tenemos todos los datos necesarios del
					// usuario
					cifrarHash();
					texto.setText(informacion);
				}
			}
		});
		menu.add(itemN1);
		
		JMenuItem itemN2 = new JMenuItem("Verificar hash");
		itemN2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				informacion = informacion + "Seleccione un archivo a verificar ...  \n";
				texto.setText(informacion);
				informacion = informacion + "Iniciando verificacion ... \n";
				texto.setText(informacion);
				ventana.add(texto);
				JFileChooser fc = new JFileChooser();
				fc.setDialogTitle("Fichero para la verificacion ");
				informacion = informacion + "Seleccionando fichero a Descifrar ...\n ";
				texto.setText(informacion);
				int seleccion = fc.showOpenDialog(fc);
				if (seleccion == JFileChooser.APPROVE_OPTION) {
					
					// Pedimos al usuario el archivo que vamos a descifrar
					File archivoElegido = fc.getSelectedFile();
					String name = archivoElegido.getAbsolutePath();
					informacion = informacion + "Archivo a cifrar";
					texto.setText("Archivo a cifrar: " + name);
					dirCifrado = name;

					Boolean Bandera = false;

					// Pedimos al usuario la contrase馻
					while (!Bandera) {
						String contrasenia01 = JOptionPane.showInputDialog("Introduce la contrase馻 de cifrado");
						String contrasenia02 = JOptionPane
								.showInputDialog("Introduce la contrase馻 de cifrado de nuevo");
						if (contrasenia01.equals(contrasenia02)) {
							Bandera = true;
						} else {
							passwordUser = contrasenia01;
							informacion = informacion + " Debe introducir la misma contrase馻 de cifrado en ambos casos";
							texto.setText(informacion);
						}
					}
					try {
						verificarHash();
						texto.setText(informacion);
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			}
		});

		menu.add(itemN2);

		JMenuItem item2 = new JMenuItem("Descifrar");
		item2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				informacion = informacion + "Seleccione un archivo a descifrar ...  \n";
				texto.setText(informacion);
				informacion = informacion + "Iniciando descifrado ... \n";
				texto.setText(informacion);
				ventana.add(texto);
				JFileChooser fc = new JFileChooser();
				fc.setDialogTitle("Fichero a Descifrar");
				informacion = informacion + "Seleccionando fichero a Descifrar ...\n ";
				texto.setText(informacion);
				int seleccion = fc.showOpenDialog(fc);
				if (seleccion == JFileChooser.APPROVE_OPTION) {
					
					// Pedimos al usuario el archivo que vamos a descifrar
					File archivoElegido = fc.getSelectedFile();
					String name = archivoElegido.getAbsolutePath();
					informacion = informacion + "Archivo a cifrar" + name +"\n";
					texto.setText(informacion);
					dirCifrado = name;

					Boolean Bandera = false;

					// Pedimos al usuario la contrase馻
					while (!Bandera) {
						String contrasenia01 = JOptionPane.showInputDialog("Introduce la contrase馻 de descifrado");
						String contrasenia02 = JOptionPane.showInputDialog("Introduce la contrase馻 de descifrado de nuevo");
						if (contrasenia01.equals(contrasenia02)) {
							Bandera = true;
						} else {
							passwordUser = contrasenia01;
							informacion = informacion + " Debe introducir la misma contrase馻 de cifrado en ambos casos";
							texto.setText(informacion);
						}
					}

					// Pedimos al usuario el directorio donde queremos guardar el fichero descifrado
					JFileChooser jfc = new JFileChooser();
					jfc.showSaveDialog(jfc);
					informacion = informacion + "Seleccione directorio a guardar el fichero \n";
					texto.setText(informacion);
					File Guardamos = jfc.getSelectedFile();
					informacion = informacion + "Guardamos el fichero con el nombre :" + Guardamos.getName() + "\n";
					texto.setText(informacion);
					dirDestCifrado = Guardamos.getAbsolutePath();
					descifrar();
				}
			}
		});

		menu.add(item2);

		JMenuItem item5 = new JMenuItem("Salir");

		item5.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				System.exit(0);
			}
		});
		menu.add(item5);

		JMenu menu2 = new JMenu("Opciones");
		JMenuItem ite = new JMenuItem("Opciones de Cifrado");

		ite.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {

				JFrame ventana2 = new JFrame("Opciones de Cifrado");
				ventana2.setLayout(null);
				ventana2.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
				ventana2.setSize(500, 400);
				ventana2.setVisible(true);

				JComboBox<String> jComboBox1;
				jComboBox1 = new JComboBox<>();
				jComboBox1.setModel(new DefaultComboBoxModel<>(new String[] { "PBEWithMD5andDES",
						"PBEWithMD5andTripleDES", "PBEWithSHA1andDESede", "PBEWithSHA1andRC2_40" }));
				jComboBox1.setLocation(100, 100);
				jComboBox1.setSize(200, 100);
				ventana2.add(jComboBox1);

				JComboBox<String> jComboBox2;
				jComboBox2 = new JComboBox<>();
				jComboBox2.setModel(new DefaultComboBoxModel<>(
						new String[] { "MD2", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512","HmacMD5", "HmacSHA1", "HmacSHA256", "HmacSHA384", "HmacSHA512" }));
				jComboBox2.setLocation(100, 200);
				jComboBox2.setSize(200, 100);
				ventana2.add(jComboBox2);
				ventana2.setVisible(true);

				jComboBox1.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						String item_seleccionado = jComboBox1.getSelectedItem().toString();
						informacion = informacion + "Hemos seleccionado el algoritmo de cifrado: " + item_seleccionado
								+ "\n";
						texto.setText(informacion);
						mode = item_seleccionado;
					}
				});

				jComboBox2.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent e) {
						String item_seleccionado = jComboBox2.getSelectedItem().toString();
						informacion = informacion + "Hemos seleccionado el algoritmo Hash/Hmac: " + item_seleccionado
								+ "\n";
						texto.setText(informacion);
						HashHmac = item_seleccionado;
					}
				});
				ventana2.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
			}
		});

		menu2.add(ite);
		menuBar.add(menu2);
		ventana.setJMenuBar(menuBar);
		ventana.setVisible(true);
	}
	
	

	/**
	 * Funci贸n principal: Ejecuta el programa en modo ventanas
	 *
	 * @param args Argumentos pasados. Dependen de si se utiliza cifrado o
	 *             descifrado.
	 */
	public static void main(String[] args) {
		MainClass m = new MainClass();
		m.ejecucion();
	}

}
