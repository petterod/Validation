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
	
	public void getNetflow() {
		for(List<String> pkt : netflow) {
			System.out.println(pkt);
		}
	}
	
	public String timestampWork(String timestamp) throws ParseException {
	   	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-ddHH:mm:ss.SSS");
		Date date = df.parse(timestamp);
		long epoch = date.getTime();
		return Long.toString(epoch);
	}
	
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
	
	
	//Ikke felt 15, det er packets på nytt
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
							netflow.get(i).get(18) + "\t" + 
							netflow.get(i).get(19) + "\t" +
							netflow.get(i).get(20) + "\t";
			formatted.add(format);
		}
	}
	
	public void getSomething() {
		System.out.println(netflow.get(1));
	}
	
	
	public void toTextFile(String FNAME) {	
		try ( BufferedWriter bw = new BufferedWriter (new FileWriter (FNAME)) ) 
		{			
			for (String line : formatted) {
				//System.out.println(line);
				bw.write(line + "\n");
			}
			System.out.println("Created file " + FNAME);
			bw.close ();
			
		} catch (IOException e) {
			e.printStackTrace ();
		}
		
	}
	
	
	public static void main(String[] args) throws ParseException, IOException {
//		FormattingNetFlow fn = new FormattingNetFlow(
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Netflow\\smallnetflow.log",
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Netflow\\O2-Netflow.dat");
			if (args.length !=2) {
		      System.err.println("usage: java -jar jarfile.jar originalInput.log formattedOutput.dat\n");
		      System.exit(-1);
		    }
		else {
			FormattingNetFlow fs = new FormattingNetFlow(args[0],args[1]);
		}
	}

}
