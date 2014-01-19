package cryptoAlgorithms;

import java.io.*;
import java.nio.charset.Charset;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static java.lang.System.out;

/**
 * Demonstrate use of CipherOutputStream and CipherInputStream to encipher and decipher a message.
 * <p/>
 * This particular version uses AES/CBC/PKCS5Padding
 * but it fairly easy to convert it to use other algorithms.
 * Requires a shared secret key.
 *
 * @author Roedy Green, Canadian Mind Products
 * @version 1.0 2008-06-17
 * @since 2008-06-17
 */
public class AES
    {
    // ------------------------------ CONSTANTS ------------------------------

    /**
     * configure with encryption algorithm to use. Avoid insecure DES. Changes to algorithm may require additional
     * ivParms.
     */
    private static final String ALGORITHM = "AES";

    /**
     * configure with block mode to use. Avoid insecure ECB.
     */
    private static final String BLOCK_MODE = "CBC";

    /**
     * configure with padding method to use
     */
    private static final String PADDING = "PKCS5Padding";

    /**
     * the encoding to use when converting bytes <--> String
     */
    private static final Charset CHARSET = Charset.forName( "UTF-8" );
    
    static Cipher cipher = null;
    static SecretKeySpec key;
    static SecretKey secretKey;

    /**
     * 128 bits worth of some random, not particularly secret, but stable bytes to salt AES-CBC with
     */
    private static final IvParameterSpec CBC_SALT = new IvParameterSpec(
            new byte[] {
                    7, 34, 56, 78, 90, 87, 65, 43,
                    12, 34, 56, 78, -123, 87, 65, 43 } );

    // -------------------------- STATIC METHODS --------------------------

    /**
     * generate a random AES style Key
     *
     * @return the AES key generated.
     * @throws java.security.NoSuchAlgorithmException
     *          if AES is not supported.
     */
    private static SecretKeySpec generateKey()
            throws NoSuchAlgorithmException
        {
        final KeyGenerator kg = KeyGenerator.getInstance( ALGORITHM );
        kg.init( 128 );// specify key size in bits
        secretKey = kg.generateKey();
        final byte[] keyAsBytes = secretKey.getEncoded();
        return new SecretKeySpec( keyAsBytes, ALGORITHM );
        }
    
    /**
     * write a plaintext message to a file enciphered.
     *
     * @param cipher    the method to use to encrypt the file.
     * @param key       the secret key to use to encrypt the file.
     * @param file      the file to write the encrypted message to.
     * @param plainText the plaintext of the message to write.
     *
     * @throws java.security.InvalidKeyException
     *                             if something is wrong with they key
     * @throws java.io.IOException if there are problems writing the file.
     * @throws java.security.InvalidAlgorithmParameterException
     *                             if problems with CBC_SALT.
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     */
    public void encrypt(String input, String output)
            throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException
        {
	    	StringBuffer plainText = new StringBuffer("");
			try {
				FileInputStream fis = new FileInputStream(input);
				BufferedReader br = new BufferedReader(new InputStreamReader(fis));
				String strLine;
				         
				        //Read File Line By Line
				        try {
							while ((strLine = br.readLine()) != null)   {
								plainText.append(strLine);
							}
						} catch (IOException e1) {
							e1.printStackTrace();
						}
	
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			}
			
	    	key = generateKey();
	    	cipher = Cipher.getInstance( ALGORITHM + "/" + BLOCK_MODE + "/" + PADDING );
	        cipher.init( Cipher.ENCRYPT_MODE, key, CBC_SALT );
	        final CipherOutputStream cout = new CipherOutputStream( new FileOutputStream( output ), cipher );
	        final byte[] plainTextBytes = plainText.toString().getBytes( CHARSET );
	        out.println( plainTextBytes.length + " plaintext bytes written" );
	        // prepend with big-endian short message length, will be encrypted too.
	        cout.write( plainTextBytes.length >>> 8 );// msb
	        cout.write( plainTextBytes.length & 0xff );// lsb
	        cout.write( plainTextBytes );
	        cout.close();
	        try {
				FileOutputStream fos = new FileOutputStream("..\\public_key.txt");
				try {
					fos.write(key.getEncoded());
				} catch (IOException e1) {
					e1.printStackTrace();
				}
			} catch (FileNotFoundException e1) {
				e1.printStackTrace();
			}
        }

    /**
     * read an enciphered file and retrieve its plaintext message.
     *
     * @param cipher method used to encrypt the file
     * @param key    secret key used to encrypt the file
     * @param file   file where the message was written.
     *
     * @return the reconstituted decrypted message.
     * @throws java.security.InvalidKeyException
     *                             if something wrong with the key.
     * @throws java.io.IOException if problems reading the file.
     */
    
    public String decrypt( String input )
            throws InvalidKeyException, IOException, InvalidAlgorithmParameterException
        {
        cipher.init( Cipher.DECRYPT_MODE, key, CBC_SALT );
        final CipherInputStream cin = new CipherInputStream( new FileInputStream( input ), cipher );
        // read big endian short length, msb then lsb
        final int messageLengthInBytes = ( cin.read() << 8 ) | cin.read();
        out.println( input.length() + " enciphered bytes in file" );
        out.println( messageLengthInBytes + " reconstituted bytes" );
        final byte[] reconstitutedBytes = new byte[ messageLengthInBytes ];
        // we can't trust CipherInputStream to give us all the data in one shot
        int bytesReadSoFar = 0;
        int bytesRemaining = messageLengthInBytes;
        while ( bytesRemaining > 0 )
            {
            final int bytesThisChunk = cin.read( reconstitutedBytes, bytesReadSoFar, bytesRemaining );
            if ( bytesThisChunk == 0 )
                {
                throw new IOException( input.toString() + " corrupted." );
                }
            bytesReadSoFar += bytesThisChunk;
            bytesRemaining -= bytesThisChunk;
            }
        cin.close();
        return new String( reconstitutedBytes, CHARSET );
        }
    
    }