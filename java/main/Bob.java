package main;

import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Bob {
	
    //instance variables      
    private boolean mac;
    private boolean enc;

    public Base64.Encoder encoder = Base64.getEncoder();
    public Base64.Decoder decoder = Base64.getDecoder();

    public Bob(String bobPort, String config) throws Exception {

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

	//notify the identity of the server to the user
	System.out.println("This is Bob");
	
	//attempt to create a server with the given port number
	int portNumber = Integer.parseInt(bobPort);
	try {
	    System.out.println("Connecting to port "+portNumber+"...");
	    ServerSocket bobServer = new ServerSocket(portNumber);
	    System.out.println("Bob Server started at port "+portNumber);
	    
	    //accept the client(a.k.a. Alice)
	    Socket clientSocket = bobServer.accept();
	    System.out.println("Client connected");
	    DataInputStream streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
			
	    boolean finished = false;
			
	    //read input from Alice
	    while(!finished) {
		try {
		    String incomingMsg = streamIn.readUTF();
		    System.out.println("Recieved msg: " + incomingMsg);
		    
		    finished = incomingMsg.equals("done");
		}
		catch(IOException ioe) {
		    //disconnect if there is an error reading the input
		    finished = true;
		}
	    }
	    
	    //clean up the connections before closing
	    bobServer.close();
	    streamIn.close();
	    System.out.println("Bob closed");
	} 
	catch (IOException e) {
	    //print error if the server fails to create itself
	    System.out.println("Error in creating the server");
	    System.out.println(e);
	}
	
    }
	
	
    /**
     * args[0] ; port that Alice will connect to
     * args[1] ; program configuration
     */
    public static void main(String[] args) {
	//check for correct # of parameters
	if (args.length != 2) {
	    System.out.println("Incorrect number of parameters");
	    return;
	}
	
	//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	
	//create Bob
	try {
	    Bob bob = new Bob(args[0], args[1]);
	} catch (Exception e) {
	    // TODO Auto-generated catch block
	    e.printStackTrace();
	}		
    }

}
