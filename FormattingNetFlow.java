package Validering;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class FormattingNetFlow {
	ArrayList<List<String>> netflow = new ArrayList<List<String>>();
	ArrayList<String> formatted = new ArrayList<String>();
	
	public FormattingNetFlow(String inputpath, String FNAME) throws IOException, ParseException {
		try (BufferedReader br = new BufferedReader(new FileReader(inputpath))) {
		    String line;
		    while ((line = br.readLine()) != null) {
		        String[] values = line.replace(" ", "").split("\\,");
		        netflow.add(Arrays.asList(values));
		    }
		}
		formatting();
		toTextFile(FNAME);
		
	}
	
	//Changes the timestamp to epoch time.
	public String timestampWork(String timestamp) throws ParseException {
	   	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-ddHH:mm:ss.SSS");
		Date date = df.parse(timestamp);
		long epoch = date.getTime();
		return Long.toString(epoch);
	}
	
	//Formats IPv6 address so they always display the complete address.
	public String formatIPv6(String address) {
		String[] list = address.split(":");
		int index = address.indexOf("::");
		String firstSub = address.substring(0,index);
		String secondSub = address.substring(index+1);
		int tall = 8 - list.length+1;
		String res = firstSub;
		for(int i = 0; i < tall; i++) {
			res += ":0";
		}
		res += secondSub;
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
	
	//Checks if bytes is displayed in k, M, G or T, or just bytes.
	public String checkPrefix(String str) {
		if(str.contains("k")) {
			String streng = str.substring(0,str.indexOf("k"));
			double num = Double.parseDouble(streng);
			return Long.toString((long) num*1000);
		}
		else if(str.contains("M")) {
			String streng = str.substring(0,str.indexOf("M"));
			double num = Double.parseDouble(streng);
			return Long.toString((long) num*1000000);
		}
		else if(str.contains("G")) {
			String streng = str.substring(0,str.indexOf("G"));
			double num = Double.parseDouble(streng);
			return Long.toString((long) num*1000000000);
		}
		else if(str.contains("T")) {
			String streng = str.substring(0,str.indexOf("T"));
			double num = Double.parseDouble(streng);
			return Long.toString((long) ((long) num*1000000000000.0));
		}
		else {
			return str;
		}
		
	}
	
	//Formats the NetFlow log. Timestamps are changed, IPv6 Addresses might be formatted if they are
	//not complete. Field 15 is skipped from the input log because it is 'packets', which is already 
	//represented in field 12.
	public void formatting() throws ParseException {
		for(int i = 1; i < netflow.size(); i++) {
			String format = timestampWork(netflow.get(i).get(0)) + "\t" +
							timestampWork(netflow.get(i).get(1)) + "\t" +
							netflow.get(i).get(2) + "\t" + 
							netflow.get(i).get(3) + "\t" + 
							checkIP(netflow.get(i).get(4)) + "\t" +
							checkIP(netflow.get(i).get(5)) + "\t" +
							netflow.get(i).get(6) + "\t" + 
							netflow.get(i).get(7) + "\t" + 
							netflow.get(i).get(8) + "\t" + 
							netflow.get(i).get(9) + "\t" + 
							netflow.get(i).get(10) + "\t" + 
							netflow.get(i).get(11) + "\t" + 
							netflow.get(i).get(12) + "\t" + 
							netflow.get(i).get(13) + "\t" + 
							netflow.get(i).get(14) + "\t" + 
							netflow.get(i).get(16) + "\t" + 
							netflow.get(i).get(17) + "\t" + 
							checkPrefix(netflow.get(i).get(18)) + "\t" + 
							netflow.get(i).get(19) + "\t" +
							netflow.get(i).get(20) + "\t";
			formatted.add(format);
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
	
	public static void main(String[] args) throws ParseException, IOException {
			if (args.length !=2) {
		      System.err.println("usage: java -jar jarfile.jar originalInput.log formattedOutput.dat\n");
		      System.exit(-1);
		    }
		else {
			FormattingNetFlow fs = new FormattingNetFlow(args[0],args[1]);
		}		
	}
}
