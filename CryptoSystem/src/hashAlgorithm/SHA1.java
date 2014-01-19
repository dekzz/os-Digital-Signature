package hashAlgorithm;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;

public class SHA1 {
	
	public static StringBuffer hash(String input, String output) throws Exception{
		 
	    MessageDigest md = MessageDigest.getInstance("SHA1");
	    FileInputStream fis = new FileInputStream(input);
	    FileOutputStream fos = new FileOutputStream(output);
	    //BufferedReader
	    byte[] inputBytes = new byte[1024];
	    
	    int nread = 0;
	 
	    while ((nread = fis.read(inputBytes)) != -1) {
	      md.update(inputBytes, 0, nread);
	    };
	 
	    byte[] mdbytes = md.digest();
	 
	    //convert the byte to hex format
	    StringBuffer sb = new StringBuffer("");
	    for (int i = 0; i < mdbytes.length; i++) {
	    	sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
	    	//sb.append(i);
	    	fos.write(sb.toString().getBytes());
	    }	    
	 
	    System.out.println("Digest(in hex format):: " + sb.toString());
	 
	    return sb;
	}
	
	/*
	public static StringBuffer hash(String input) throws Exception{
		 
	    MessageDigest md = MessageDigest.getInstance("SHA1");
	    FileInputStream fis = new FileInputStream(input);
	    //BufferedReader
	    byte[] inputBytes = new byte[1024];
	    
	    int nread = 0;
	 
	    while ((nread = fis.read(inputBytes)) != -1) {
	      md.update(inputBytes, 0, nread);
	    };
	 
	    byte[] mdbytes = md.digest();
	    
	    //convert the byte to hex format
	    StringBuffer sb = new StringBuffer("");
	    for (int i = 0; i < mdbytes.length; i++) {
	    	sb.append(Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1));
	    }	    
	 
	    System.out.println("Digest(in hex format):: " + sb.toString());
	 
	    return sb;
	}
	*/

}