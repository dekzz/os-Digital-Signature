import hashAlgorithm.SHA1;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.SWT;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Text;
import org.eclipse.wb.swt.SWTResourceManager;
import org.eclipse.swt.widgets.Combo;
import org.eclipse.swt.events.MouseAdapter;
import org.eclipse.swt.events.MouseEvent;

import cryptoAlgorithms.AES;
import cryptoAlgorithms.RSA;


public class CryptoSystem{
	private static Text textboxInput;
	private static Text textboxOutput;
	private static Text textboxSenderHash;
	private static Text textboxReceiverHash;
	private static Text textboxPublicKey;
	private static Text textboxPrivateKey;
	private static String inputPath;

	/**
	 * @param args
	 */
	public static void main(String[] args){
		
		final RSA rsa = new RSA(2048);
		final AES aes = new AES();

		Display display = new Display();
		final Shell mainWindow = new Shell(display);
		mainWindow.setImage(SWTResourceManager.getImage("..\\cryptography-icon.gif"));
		mainWindow.setSize(770, 568);
		mainWindow.setText("CryptoGenesis");
		
		textboxInput = new Text(mainWindow, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		textboxInput.setBounds(10, 66, 363, 129);
		
		textboxOutput = new Text(mainWindow, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		textboxOutput.setBounds(379, 66, 365, 129);
		
		textboxSenderHash = new Text(mainWindow, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		textboxSenderHash.setBounds(10, 232, 363, 136);
		
		textboxReceiverHash = new Text(mainWindow, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		textboxReceiverHash.setBounds(379, 232, 365, 136);
		
		textboxPublicKey = new Text(mainWindow, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		textboxPublicKey.setBounds(10, 405, 363, 115);
		
		textboxPrivateKey = new Text(mainWindow, SWT.BORDER | SWT.READ_ONLY | SWT.WRAP | SWT.V_SCROLL | SWT.MULTI);
		textboxPrivateKey.setBounds(379, 405, 365, 115);
		
		final Label lblFilepath = new Label(mainWindow, SWT.NONE);
		lblFilepath.setBounds(91, 15, 419, 15);
		
		final Label lblResult = new Label(mainWindow, SWT.RIGHT);
		lblResult.setBounds(472, 45, 272, 15);
		
		Label lblPlainText = new Label(mainWindow, SWT.RIGHT);
		lblPlainText.setBounds(318, 45, 55, 15);
		lblPlainText.setText("Input");
		
		Label lblEncryptedText = new Label(mainWindow, SWT.NONE);
		lblEncryptedText.setBounds(379, 45, 87, 15);
		lblEncryptedText.setText("Output");
		
		Label lblSenderHash = new Label(mainWindow, SWT.NONE);
		lblSenderHash.setBounds(10, 211, 66, 15);
		lblSenderHash.setText("Sender Hash");
		
		Label lblReceiverHash = new Label(mainWindow, SWT.NONE);
		lblReceiverHash.setBounds(379, 211, 80, 15);
		lblReceiverHash.setText("Receiver Hash");
		
		Label lblGeneratedPublicKey = new Label(mainWindow, SWT.NONE);
		lblGeneratedPublicKey.setBounds(10, 384, 112, 15);
		lblGeneratedPublicKey.setText("Generated Public Key");
		
		Label lblGeneratedPrivateKey = new Label(mainWindow, SWT.NONE);
		lblGeneratedPrivateKey.setBounds(379, 384, 122, 15);
		lblGeneratedPrivateKey.setText("Generated Private Key");
		
		final Combo cboxEncryption = new Combo(mainWindow, SWT.READ_ONLY);
		cboxEncryption.setItems(new String[] {"AES", "RSA"});
		cboxEncryption.setBounds(653, 12, 91, 23);
		cboxEncryption.select(0);
		
		final Button btnEncrypt = new Button(mainWindow, SWT.NONE);
		btnEncrypt.setEnabled(false);
		btnEncrypt.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				String output = "..\\encrypted.txt";
				
				if(cboxEncryption.getSelectionIndex() == 0){
					try {
						aes.encrypt(inputPath, output);
					} catch (InvalidKeyException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (InvalidAlgorithmParameterException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (NoSuchAlgorithmException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (NoSuchPaddingException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (IOException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					}
					StringBuffer sb = new StringBuffer("");
					try {
						FileInputStream fis = new FileInputStream(output);
						BufferedReader br = new BufferedReader(new InputStreamReader(fis));
						String strLine;
						         
						        //Read File Line By Line
						        try {
									while ((strLine = br.readLine()) != null)   {
									    sb.append(strLine);
									}
								} catch (IOException e1) {
									e1.printStackTrace();
								}
						        textboxOutput.setText(sb.toString());

					} catch (FileNotFoundException e1) {
						e1.printStackTrace();
					}
				}
				else{
					StringBuffer sb = new StringBuffer("");
					try {
						FileInputStream fis = new FileInputStream(inputPath);
						BufferedReader br = new BufferedReader(new InputStreamReader(fis));
						String strLine;
						         
						        //Read File Line By Line
						        try {
									while ((strLine = br.readLine()) != null)   {
									    sb.append(strLine);
									}
									System.out.println(sb.toString());
								} catch (IOException e1) {
									e1.printStackTrace();
								}
					} catch (FileNotFoundException e2) {
						e2.printStackTrace();
					}
					
					rsa.generateKeys();
					String encrypted = rsa.encrypt(sb.toString());
					System.out.println(encrypted);
					textboxOutput.setText(encrypted);
					
					try {
						FileOutputStream fos = new FileOutputStream(output);
						try {
							fos.write(encrypted.getBytes(), 0, encrypted.length());
						} catch (IOException e1) {
							e1.printStackTrace();
						}
					} catch (FileNotFoundException e1) {
						e1.printStackTrace();
					}
					
				}
			}
		});
		btnEncrypt.setBounds(10, 40, 75, 25);
		btnEncrypt.setText("Encrypt");
		
		final Button btnDecrypt = new Button(mainWindow, SWT.NONE);
		btnDecrypt.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				String output = "..\\decrypted.txt";
				String decrypted = "";
				
				if(cboxEncryption.getSelectionIndex() == 0){
					
					try {
						decrypted = aes.decrypt(inputPath);
						textboxOutput.setText(decrypted);
					} catch (InvalidKeyException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (InvalidAlgorithmParameterException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					} catch (IOException e2) {
						// TODO Auto-generated catch block
						e2.printStackTrace();
					}
					
					try {
						FileOutputStream fos = new FileOutputStream(output);
						try {
							fos.write(decrypted.getBytes(), 0, decrypted.length());
						} catch (IOException e1) {
							e1.printStackTrace();
						}
					} catch (FileNotFoundException e1) {
						e1.printStackTrace();
					}
				}
				else{
					StringBuffer sb = new StringBuffer("");
					try {
						FileInputStream fis = new FileInputStream(inputPath);
						BufferedReader br = new BufferedReader(new InputStreamReader(fis));
						String strLine;
						         
						        //Read File Line By Line
						        try {
									while ((strLine = br.readLine()) != null)   {
									    sb.append(strLine);
									}
									System.out.println(sb.toString());
								} catch (IOException e1) {
									e1.printStackTrace();
								}
					} catch (FileNotFoundException e2) {
						e2.printStackTrace();
					}
					
					decrypted = rsa.decrypt(sb.toString());
					System.out.println(decrypted);
					textboxOutput.setText(decrypted);
					
					try {
						FileOutputStream fos = new FileOutputStream(output);
						try {
							fos.write(decrypted.getBytes(), 0, decrypted.length());
						} catch (IOException e1) {
							e1.printStackTrace();
						}
					} catch (FileNotFoundException e1) {
						e1.printStackTrace();
					}

				}
			}
		});
		btnDecrypt.setEnabled(false);
		btnDecrypt.setBounds(86, 40, 75, 25);
		btnDecrypt.setText("Decrypt");
		
		final Button btnSignature = new Button(mainWindow, SWT.NONE);
		btnSignature.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				
				String output = "..\\sender_hash.txt";
				
				StringBuffer sb = new StringBuffer("");
				StringBuffer hash = new StringBuffer("");
				try {
					FileInputStream fis = new FileInputStream(inputPath);
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String strLine;
					         
					        //Read File Line By Line
					        try {
								while ((strLine = br.readLine()) != null)   {
								    sb.append(strLine);
								}
								System.out.println(sb.toString());
							} catch (IOException e1) {
								e1.printStackTrace();
							}
				} catch (FileNotFoundException e2) {
					e2.printStackTrace();
				}
				
				try {
					FileOutputStream fos = new FileOutputStream("..\\signature_text.txt");
					try {
						fos.write(sb.toString().getBytes());
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				} catch (FileNotFoundException e1) {
					e1.printStackTrace();
				}
				
				try {
					SHA1.hash(inputPath, output);
				} catch (Exception e2) {
					e2.printStackTrace();
				}
				
				try {
					FileInputStream fis = new FileInputStream(output);
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String strLine;
					         
					        //Read File Line By Line
					        try {
								while ((strLine = br.readLine()) != null)   {
								    hash.append(strLine);
								}
								System.out.println(hash.toString());
							} catch (IOException e1) {
								e1.printStackTrace();
							}
				} catch (FileNotFoundException e2) {
					e2.printStackTrace();
				}
				
				rsa.generateKeys();
				String encrypted = rsa.encrypt(hash.toString());
				
				try {
					FileOutputStream fos = new FileOutputStream("..\\signature_cHash.txt");
					try {
						fos.write(encrypted.getBytes(), 0, encrypted.length());
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				} catch (FileNotFoundException e1) {
					e1.printStackTrace();
				}
				
				String signature = sb + "\n\n" + encrypted;
				System.out.println("Signature: " + signature);
				textboxOutput.setText(signature);
				
				try {
					FileOutputStream fos = new FileOutputStream("..\\encrypted.txt");
					try {
						fos.write(signature.getBytes());
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				} catch (FileNotFoundException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnSignature.setEnabled(false);
		btnSignature.setBounds(162, 40, 75, 25);
		btnSignature.setText("Signature");
		
		final Button btnCheck = new Button(mainWindow, SWT.NONE);
		btnCheck.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				
				String output = "..\\decrypted.txt";
				StringBuffer plainText = new StringBuffer("");
				StringBuffer encryptedHash = new StringBuffer("");
				StringBuffer reHashed = new StringBuffer("");
				
				try {
					FileInputStream fis = new FileInputStream("..\\signature_text.txt");
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String strLine;
				         
			        	//Read File Line By Line
				        try {
							while ((strLine = br.readLine()) != null)   {
							    plainText.append(strLine);
							}
							System.out.println("Plain text:" + plainText.toString());
						} catch (IOException e1) {
							e1.printStackTrace();
						}
				} catch (FileNotFoundException e2) {
					e2.printStackTrace();
				}
				
				try {
					FileInputStream fis = new FileInputStream("..\\signature_cHash.txt");
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String strLine;
				         
			        	//Read File Line By Line
				        try {
							while ((strLine = br.readLine()) != null)   {
							    encryptedHash.append(strLine);
							}
							System.out.println("Encripted hash:" + encryptedHash);
						} catch (IOException e1) {
							e1.printStackTrace();
						}
				} catch (FileNotFoundException e2) {
					e2.printStackTrace();
				}
				
				//decryption problem?!
				String decrypted = rsa.decrypt(encryptedHash.toString());
				try {
					FileOutputStream fos = new FileOutputStream("..\\signature_dHash.txt");
					try {
						fos.write(decrypted.getBytes(), 0, decrypted.length());
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				} catch (FileNotFoundException e1) {
					e1.printStackTrace();
				}

				String reText = plainText.toString() + "\n\n" +  decrypted;
				System.out.println("Reconstructed: " + reText);
				textboxOutput.setText(reText);
				
				try {
					FileOutputStream fos = new FileOutputStream(output);
					try {
						fos.write(reText.getBytes(), 0, reText.length());
					} catch (IOException e1) {
						e1.printStackTrace();
					}
				} catch (FileNotFoundException e1) {
					e1.printStackTrace();
				}
				
				try {
					SHA1.hash("..\\signature_text.txt", "..\\receiver_hash.txt");
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				try {
					FileInputStream fis = new FileInputStream("..\\receiver_hash.txt");
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String strLine;
				         
			        	//Read File Line By Line
				        try {
							while ((strLine = br.readLine()) != null)   {
							    reHashed.append(strLine);
							}
							System.out.println("Receiver hash:" + reHashed.toString());
						} catch (IOException e1) {
							e1.printStackTrace();
						}
				} catch (FileNotFoundException e2) {
					e2.printStackTrace();
				}
				textboxReceiverHash.setText(reHashed.toString());
				
				if(reHashed.toString().equals(decrypted) ){
					lblResult.setText("Hash Match! Valid Digital Signature!");
				}
				else{
					lblResult.setText("Hash Missmatch! Invalid Digital Signature!");
				}
			}
		});
		btnCheck.setEnabled(false);
		btnCheck.setBounds(237, 40, 75, 25);
		btnCheck.setText("Check");
		
		final Button btnHashSender = new Button(mainWindow, SWT.NONE);
		btnHashSender.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				String output = "..\\sender_hash.txt";
				StringBuffer sb = new StringBuffer("");
				try {
					SHA1.hash(inputPath, output);
					//textboxSenderHash.setText(sb.toString());
					try {
						FileInputStream fis = new FileInputStream("..\\sender_hash.txt");
						BufferedReader br = new BufferedReader(new InputStreamReader(fis));
						String strLine;
						         
						        //Read File Line By Line
						        try {
									while ((strLine = br.readLine()) != null)   {
									    sb.append(strLine);
									}
									System.out.println(sb.toString());
								} catch (IOException e1) {
									e1.printStackTrace();
								}
					} catch (FileNotFoundException e2) {
						e2.printStackTrace();
					}
					textboxSenderHash.setText(sb.toString());
				} catch (Exception e2) {
					e2.printStackTrace();
				}
			}
		});
		btnHashSender.setEnabled(false);
		btnHashSender.setBounds(298, 201, 75, 25);
		btnHashSender.setText("Hash");
		
		final Button btnHashReceiver = new Button(mainWindow, SWT.NONE);
		btnHashReceiver.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				String output = "..\\receiver_hash.txt";
				StringBuffer sb = new StringBuffer("");
				try {
					SHA1.hash("..\\decrypted.txt", output);
					//textboxReceiverHash.setText(sb.toString());
					try {
						FileInputStream fis = new FileInputStream("..\\receiver_hash.txt");
						BufferedReader br = new BufferedReader(new InputStreamReader(fis));
						String strLine;
						         
						        //Read File Line By Line
						        try {
									while ((strLine = br.readLine()) != null)   {
									    sb.append(strLine);
									}
									System.out.println(sb.toString());
								} catch (IOException e1) {
									e1.printStackTrace();
								}
					} catch (FileNotFoundException e2) {
						e2.printStackTrace();
					}
					textboxReceiverHash.setText(sb.toString());
				} catch (Exception e2) {
					e2.printStackTrace();
				}
				if(textboxReceiverHash.getText().equals(textboxSenderHash.getText()) ){
					lblResult.setText("Hash Match! Valid Digital Signature!");
				}
				else{
					lblResult.setText("Hash Missmatch! Invalid Digital Signature!");
				}
			}
		});
		btnHashReceiver.setEnabled(false);
		btnHashReceiver.setBounds(669, 201, 75, 25);
		btnHashReceiver.setText("Hash");
		
		final Button btnShowPublic = new Button(mainWindow, SWT.NONE);
		btnShowPublic.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				StringBuffer sb = new StringBuffer("");
				try {
					FileInputStream fis = new FileInputStream("..\\public_key.txt");
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String strLine;
					         
					        //Read File Line By Line
					        try {
								while ((strLine = br.readLine()) != null)   {
								    sb.append(strLine);
								}
								System.out.println("Public key: " + sb.toString());
							} catch (IOException e1) {
								e1.printStackTrace();
							}
				} catch (FileNotFoundException e2) {
					e2.printStackTrace();
				}
				textboxPublicKey.setText(sb.toString());
			}
		});
		btnShowPublic.setEnabled(false);
		btnShowPublic.setBounds(298, 374, 75, 25);
		btnShowPublic.setText("Show");
		
		final Button btnShowPrivate = new Button(mainWindow, SWT.NONE);
		btnShowPrivate.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				StringBuffer sb = new StringBuffer("");
				try {
					FileInputStream fis = new FileInputStream("..\\private_key.txt");
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String strLine;
					         
					        //Read File Line By Line
					        try {
								while ((strLine = br.readLine()) != null)   {
								    sb.append(strLine);
								}
								System.out.println("Private key: " + sb.toString());
							} catch (IOException e1) {
								e1.printStackTrace();
							}
				} catch (FileNotFoundException e2) {
					e2.printStackTrace();
				}
				textboxPrivateKey.setText(sb.toString());
			}
		});
		btnShowPrivate.setEnabled(false);
		btnShowPrivate.setBounds(669, 374, 75, 25);
		btnShowPrivate.setText("Show");
		
		Button btnOpenFile = new Button(mainWindow, SWT.NONE);
		btnOpenFile.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseDown(MouseEvent e) {
				org.eclipse.swt.widgets.FileDialog fd = new org.eclipse.swt.widgets.FileDialog(mainWindow);
				inputPath = fd.open();
				lblFilepath.setText(inputPath);
				try {
					FileInputStream fis = new FileInputStream(inputPath);
					BufferedReader br = new BufferedReader(new InputStreamReader(fis));
					String strLine;
					         
					        //Read File Line By Line
					        try {
					        	textboxInput.setText("");
								while ((strLine = br.readLine()) != null)   {
								    textboxInput.append(strLine);
								}
								btnEncrypt.setEnabled(true);
								btnDecrypt.setEnabled(true);
								btnHashSender.setEnabled(true);
								btnHashReceiver.setEnabled(true);
								btnShowPublic.setEnabled(true);
								btnShowPrivate.setEnabled(true);
								btnSignature.setEnabled(true);
								btnCheck.setEnabled(true);
							}
					        catch (IOException e1) {
								e1.printStackTrace();
							}
				} 
				catch (FileNotFoundException e1) {
					e1.printStackTrace();
				}
			}
		});
		btnOpenFile.setBounds(10, 10, 75, 25);
		btnOpenFile.setText("Open File");
		
		mainWindow.open();
		
		while (!mainWindow.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
		display.dispose();
		
	}
}