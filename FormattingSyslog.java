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

public class FormattingSyslog {
	ArrayList<List<String>> syslog = new ArrayList<List<String>>();
	ArrayList<String> formatted = new ArrayList<String>();
	
	public FormattingSyslog(String inputpath,String FNAME) throws FileNotFoundException, ParseException {
		Scanner s = new Scanner(new File(inputpath));
		while(s.hasNextLine()) {	
			syslog.add(new ArrayList<String>(Arrays.asList(s.nextLine().split(" "))));
		}
		s.close();
		formatting();
		toTextFile(FNAME);
	}
	
	public String timestampWork(String timestamp) throws ParseException {
		
	   	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:sszzz");
		Date date = df.parse(timestamp);
		long epoch = date.getTime();
		return Long.toString(epoch);
	}
	
	public void formatting() throws ParseException {
		for(int i = 1; i < syslog.size(); i++) {
			String format = "";
			format += timestampWork(syslog.get(i).get(0)) + "\t";
			format += syslog.get(i).get(1) + "\t";
			format += syslog.get(i).get(2).substring(0,syslog.get(i).get(2).length()-1) + "\t";
			if(syslog.get(i).size() > 3) {
				for(int j = 3; j<syslog.get(i).size(); j++) {
					format += syslog.get(i).get(j) + " ";
				}
			}
			else {
				format += " " + "\t";
			}
			formatted.add(format);
		}
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
	
	
	public static void main(String[] args) throws FileNotFoundException, ParseException {
		FormattingSyslog fw = new FormattingSyslog(
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Syslog\\syslog-iso-time-example2.log",
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Syslog\\O2-Syslog.dat");
//			if (args.length !=2) {
//		      System.err.println("usage: java -jar jarfile.jar originalInput.log formattedOutput.dat\n");
//		      System.exit(-1);
//		    }
//		else {
//			FormattingSyslog fs = new FormattingSyslog(args[0],args[1]);
//		}		
	}

}
