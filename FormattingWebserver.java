package Validering;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

public class FormattingWebserver {
	ArrayList<List<String>> weblog = new ArrayList<List<String>>();
	ArrayList<String> formatted = new ArrayList<String>();
	
	public FormattingWebserver(String inputpath, String FNAME) throws FileNotFoundException, ParseException {
		Scanner s = new Scanner(new File(inputpath));
		while(s.hasNextLine()) {	
			weblog.add(new ArrayList<String>(Arrays.asList(s.nextLine().split(" "))));
		}
		s.close();
		formatting();
		toTextFile(FNAME);
	}
	
	//Changes the timestamp to epoch time.
	public String timestampWork(String timestamp) throws ParseException {
	   	SimpleDateFormat df = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss zzz");
		Date date = df.parse(timestamp);
		long epoch = date.getTime();
		return Long.toString(epoch);
	}
	
	//Formats IPv6 address so they always display the complete address.
	public String formatIPv6(String address) {
		String[] liste = address.split(":");
		int index = address.indexOf("::");
		String first = address.substring(0,index);
		String second = address.substring(index+1);
		int tall = 8 - liste.length+1;
		String res = first;
		for(int i = 0; i < tall; i++) {
			res += ":0";
		}
		res += second;
		return res;
	}
	
	//Checks if the IP address is version 4 or 6, and if version 6 is complete or not.
	public String checkIP(String ip) {
		if(ip.contains(".")) {
			return ip;
		}
		else if(ip.indexOf("::") == -1){
			return ip;
		}
		else {
			return formatIPv6(ip);
		}
	}
	
	//Checks if the request method used is a valid one.
	public String checkRequestMethod(String requestMethod) {
		ArrayList<String> requestMethods = new ArrayList<String>(Arrays.asList("GET","HEAD","POST","PUT","DELETE","TRACE",
			"OPTIONS","CONNECT","PATCH"));
		if(requestMethods.contains(requestMethod)) {
			return requestMethod;
		}
		else {
			return "-";
		}
	}
	
	//Checks if the HTTP-version used is a valid one.
	public String checkHTTPversion(String httpVersion) {
		ArrayList<String> allowedVersions = new ArrayList<String>(Arrays.asList("HTTP/1.1","HTTP/2.0","HTTP/3.0",
				"HTTP/0.9","HTTP/1.0"));
		if(allowedVersions.contains(httpVersion)) {
			return httpVersion;
		}
		else {
			return "-";
		}
	}
	
	//Formats the web server log. Timestamps are changed, IPv6 Addresses might be formatted if they are
	//not complete. The Request Line of a web server log is split into Request Method, Request and HTTP-Version.
	public void formatting() throws ParseException {
		for(List<String> pkt : weblog) {
			String format = "";
			format += checkIP(pkt.get(0)) + "\t";
			format += "-" + "\t";
			format += "-" + "\t";
			format += timestampWork(pkt.get(3).substring(1) + " " + pkt.get(4).substring(0,pkt.get(4).length()-1))
					+ "\t";
			if(!pkt.get(5).substring(1, pkt.get(5).length()-1).equals("-") &&
					pkt.get(5).contains("\"") && pkt.get(5).indexOf("\"",1)==-1) {
				format += checkRequestMethod(pkt.get(5).substring(1)) + "\t";
				if(pkt.get(7).contains("\"")) {
					format += pkt.get(6) + "\t";
					format += checkHTTPversion(pkt.get(7).substring(0,pkt.get(7).length()-1)) + "\t";
					format += pkt.get(8) + "\t";
					format += pkt.get(9) + "\t";
					formatted.add(format);
				}
				else {
					for(int i = 6; i < pkt.size();i++) {
						if(pkt.get(i).contains("\"")) {
							System.out.println("pkt " + pkt);
							format += "\t" + checkHTTPversion(pkt.get(i).substring(0,pkt.get(i).length()-1)) + "\t";
							format += pkt.get(i+1) + "\t" + pkt.get(i+2) + "\t";
							break;
						}
						else {
							format += pkt.get(i) + " ";
						}
					}
					formatted.add(format);
				}
			}
			else {
				format += "-" + "\t" + "-" + "\t" + "-" + "\t";
				format += pkt.get(6) + "\t";
				format += pkt.get(7) + "\t";
				formatted.add(format);
			}
		}
	}
	
	//Method for writing the new log to text file.
	public void toTextFile(String FNAME) {
		try ( BufferedWriter bw = new BufferedWriter (new FileWriter (FNAME)) ) 
		{			
			for (String line : formatted) {
				bw.write(line + "\n");
			}
			System.out.println("Created file " + FNAME);
			bw.close ();
			
		} catch (IOException e) {
			e.printStackTrace ();
		}
		
	}
	
	
	public static void main(String[] args) throws FileNotFoundException, ParseException {
		if (args.length !=2) {
	      System.err.println("usage: java -jar jarfile.jar originalInput.log formattedOutput.dat\n");
	      System.exit(-1);
	    }
		else {
			FormattingWebserver fs = new FormattingWebserver(args[0],args[1]);
		}	
	}
}
