package main;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Alice {
	
    //instance variables
    private boolean mac;
    private boolean enc;

    public Base64.Encoder encoder = Base64.getEncoder();
    public Base64.Decoder decoder = Base64.getDecoder();

    
    public Alice(String serverPortStr, String config)
	throws Exception {
		
	//Apply configuration
	if(config.compareTo("noCrypto") == 0){
	    mac = false;
	    enc = false;
	} else if(config.compareTo("enc") == 0){
	    mac = false;
	    enc = true;
	} else if(config.compareTo("mac") == 0){
	    mac = true;
	    enc = false;
	} else if(config.compareTo("EncThenMac") == 0){
	    mac = true;
	    enc = true;
	}

	Scanner console = new Scanner(System.in);
	System.out.println("This is Alice"); 
	    
	//obtain server's port number and connect to it
	int serverPort = Integer.parseInt(serverPortStr);
	String serverAddress = "localhost";
	    
	try{
	    System.out.println("Connecting to Server at ("+serverPort+", "+serverAddress +")...");
	    Socket serverSocket = new Socket(serverAddress, serverPort);
	    System.out.println("Connected to Server");
		
	    DataOutputStream streamOut = new DataOutputStream(serverSocket.getOutputStream());
		
			
	    //obtain the message from the user and send it to Server
	    //the communication ends when the user inputs "done"
	    String line = "";
	    while(!line.equals("done")) {
		try {  
		    System.out.print("Type message: ");
		    line = console.nextLine();
			
		    String packagedMsg = packageMessage(line);
		    streamOut.writeUTF(packagedMsg);
		    streamOut.flush();
		    System.out.println("Message sent");
			
		} catch(IOException ioe) {  
		    System.out.println("Sending error: " + ioe.getMessage());
		}
	    }
		
	    //close all the sockets and console 
	    console.close();
	    streamOut.close();
	    serverSocket.close();
		
	}
	catch(IOException e) {
	    //print error
	    System.out.println("Connection failed due to following reason");
	    System.out.println(e);
	}
    }
	
    
    private String packageMessage(String message) throws Exception {
	StringBuilder acc = new StringBuilder();
	acc.append(message);
	
	return acc.toString();
    }
    
    /**
     * args[0] ; port that Alice will connect to (Mallory's port)
     * args[1] ; program configuration
     */
    public static void main(String[] args) {
	
	//check for correct # of parameters
	if(args.length != 2) {
	    System.out.println("Incorrect number of parameters");
	} else {
	    //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	    
	    //create Alice to start communication
	    try {
		Alice alice = new Alice(args[0], args[1]);
	    } catch (Exception e) {
		e.printStackTrace();
	    }
	}
	
    }
}
