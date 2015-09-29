/***********************************************************************
 * SimpleWebServer.java
 * <p>
 * <p>
 * This toy web server is used to illustrate security vulnerabilities.
 * This web server only supports extremely simple HTTP GET requests.
 * <p>
 * This file is also available at http://www.learnsecurity.com/ntk
 ***********************************************************************/

package com.learnsecurity;

import java.io.*;
import java.net.*;
import java.security.AccessControlException;
import java.util.*;

public class SimpleWebServer {

    /* Run the HTTP server on this TCP port. */
    private static final int PORT = 8080;

    /* The socket used to process incoming connections
       from web clients */
    private static ServerSocket dServerSocket;

    public SimpleWebServer() throws Exception {
        dServerSocket = new ServerSocket(PORT);
    }

    public void run() throws Exception {
        while (true) {
         /* wait for a connection from a client */
            Socket s = dServerSocket.accept();
 
 	    /* then process the client's request */
            processRequest(s);
        }
    }

    private String CONTENT_LENGTH_KEY = "Content-Length";

    /* Reads the HTTP request from the client, and
       responds with the file the user requested or
       a HTTP error code. */
    public void processRequest(Socket s) throws Exception { 
 	/* used to read data from the client */
        BufferedReader br =
                new BufferedReader(
                        new InputStreamReader(s.getInputStream()));
 
 	/* used to write data to the client */
        OutputStreamWriter osw =
                new OutputStreamWriter(s.getOutputStream());
     
 	/* read the HTTP request from the client */
        String request = br.readLine();

        String command = null;
        String pathname = null;
        String protocolInfo = null;
     
 	/* parse the HTTP request */
        StringTokenizer st =
                new StringTokenizer(request, " ");

        //makes sure a command is provided
        if (st.hasMoreTokens()) {
            command = st.nextToken();
        }
        else {
            writeAndClose(osw, "HTTP/1.0 400 Bad Request\n\n");
            return;
        }

        //makes sure a pathname is provided
        if (st.hasMoreTokens()) {
            pathname = st.nextToken();
        }
        else {
            writeAndClose(osw, "HTTP/1.0 400 Bad Request\n\n");
            return;
        }

        //makes sure a protocol is provided
        if (st.hasMoreTokens()) {
            protocolInfo = st.nextToken();
        }
        else {
            writeAndClose(osw, "HTTP/1.0 400 Bad Request\n\n");
            return;
        }

        //avoids more than 3 parameters
        if (st.hasMoreTokens()) {
            writeAndClose(osw, "HTTP/1.0 400 Bad Request\n\n");
            return;
        }

        //makes sure the resource path is less than 1KB
        final byte[] utf8Bytes = pathname.getBytes("UTF-8");
        if (utf8Bytes.length > 1000) {
            writeAndClose(osw, "HTTP/1.0 414 Request-URI Too Long\n\n");
            return;
        }

        String[] infoSplit = protocolInfo.split("/");
        String protocol = infoSplit[0];
        String version = infoSplit[1];

        //check to see that version and protocol could be split properly
        if (protocol == null || version == null){
            writeAndClose(osw, "HTTP/1.0 400 Bad Request\n\n");
            return;
        }

        //makes sure the http version is 1.1 or 1.0
        boolean isValidVersion = version.equals("1.1") || version.equals("1.0");
        //makes sure that protocol is HTTP
        boolean isValidProtocol = protocol.equals("HTTP");

        if (!isValidVersion) {
            writeAndClose(osw, "HTTP/1.0 505 HTTP Version Not Supported\n\n");
            return;
        }

        if (!isValidProtocol) {
            writeAndClose(osw, "HTTP/1.0 400 Bad Request\n\n");
            return;
        }

        //gets the canonical path of the working directory,
        // and the specified path,
        // and makes sure that the specified path is a sub
        // file or directory of the working directory
        File file = new File(pathname);
        File currentDir = new File(".");
        String filepath = file.getCanonicalPath();
        String currentpath = currentDir.getCanonicalPath();
        boolean startsWith = filepath.startsWith(currentpath);
        if (!startsWith){
            writeAndClose(osw, "HTTP/1.0 403 Forbidden\n\n");
            return;
        }

        Map requestHeaders = null;
        boolean caughtException = false;
        try {
            requestHeaders = requestHeadersFromReader(br);
        } catch (IOException e) {
            caughtException = true;
        } catch (HeaderFormatException e) {
            System.out.println("Header Exception");
            caughtException = true;
        }

        //makes sure the headers could be properly parsed and that headers map isnt null
        if (caughtException || requestHeaders == null){
            writeAndClose(osw, "HTTP/1.0 400 Bad Request\n\n");
            return;
        }

        if (command.equals("GET")) {
                 /* if the request is a GET
               try to respond with the file
               the user is requesting */
            serveFile(osw, pathname);
        }
        else if (command.equals("PUT")) {
            String contentLengthString = (String)requestHeaders.get(CONTENT_LENGTH_KEY);
            //content length value must exist and by the get method returning null,
            // that means the key did not exist or the value for that header was null,
            // neither of which is accepted
            if (contentLengthString != null) {
                int contentLength = Integer.parseInt(contentLengthString);
                putFile(br, osw, contentLength, pathname);
            }
            else {
                osw.write("HTTP/1.0 411 Length Required\n\n");
            }
        }
        else {
                /* if the request is a NOT a GET,
               return an error saying this server
               does not implement the requested command */
            osw.write("HTTP/1.0 501 Not Implemented\n\n");
        }

        /* close the connection to the client */
        osw.close();
    }

    private void writeAndClose(OutputStreamWriter writer, String string) throws IOException {
        writer.write(string);
        writer.close();
    }

    private class HeaderFormatException extends Exception {}

    private Map<String, String> requestHeadersFromReader(BufferedReader headerReader) throws HeaderFormatException, IOException {
        Map<String, String> headerMap = new HashMap<String, String>();

        String line;
        while (!(line = headerReader.readLine()).isEmpty()){
            System.out.println(line+"*");
            String[] headerValueSplit = line.split(": ");
            String name = headerValueSplit[0];
            String value = headerValueSplit[1];

            if (name.endsWith(" ") || name == null || value == null || value.startsWith(" ")) {
                throw new HeaderFormatException();
            }

            headerMap.put(name, value);
        }

        return headerMap;
    }

    public void putFile(BufferedReader fileInput,
                        OutputStreamWriter osw,
                        int contentLength,
                        String pathname) throws Exception{
        BufferedWriter fileWriter = null;
        try {
            String response;

            File f = new File(pathname);
            f.setWritable(true, false);
            System.out.println("created file");
            if (f != null && f.isFile()) {
                response = "HTTP/1.0 201 Created\n\n";
            } else {
                response = "HTTP/1.0 200 OK\n\n";
            }

            fileWriter = new BufferedWriter(new FileWriter(f));
            String line = null;
            System.out.println(contentLength+"");
            System.out.println("writing to file");
            fileInput.readLine();
            int i = 0;
            while (i < contentLength) {
                fileWriter.write(fileInput.read());
                i++;
            }
//            while((line = fileInput.readLine()) != null && !line.isEmpty()){
//                System.out.println(line);
//                fileWriter.write(line);
//            }
            System.out.println("wrote to file");
            osw.write(response);
        }
        catch (Exception e) {
            System.out.println(e.getMessage() +" "+e.getCause());
            osw.write ("HTTP/1.0 400 Bad Request\n\n");
            return;
        } finally {
            System.out.println("finally block");
            fileWriter.close();
        }
    }

    public void serveFile(OutputStreamWriter osw,
                          String pathname) throws Exception {
        System.out.println(pathname);
        FileReader fr = null;
        int c = -1;
        StringBuffer sb = new StringBuffer();
       
 	/* remove the initial slash at the beginning
 	   of the pathname in the request */
        if (pathname.charAt(0) == '/')
            pathname = pathname.substring(1);
 	
 	/* if there was no filename specified by the
 	   client, serve the "index.html" file */
        if (pathname.equals(""))
            pathname = "index.html";
 
 	/* try to open file specified by pathname */
        try {
            fr = new FileReader(pathname);
            c = fr.read();
        } catch (Exception e) {
 	    /* if the file is not found,return the
 	       appropriate HTTP response code  */
            osw.write("HTTP/1.0 404 Not Found\n\n");
            return;
        }
 
 	/* if the requested file can be successfully opened
 	   and read, then return an OK response code and
 	   send the contents of the file */
        osw.write("HTTP/1.0 200 OK\n\n");
        while (c != -1) {
            sb.append((char) c);
            c = fr.read();
        }
        osw.write(sb.toString());
    }

    /* This method is called when the program is run from
       the command line. */
    public static void main(String argv[]) throws Exception {
 
 	/* Create a SimpleWebServer object, and run it */
        SimpleWebServer sws = new SimpleWebServer();
        sws.run();
    }
}                                                              
