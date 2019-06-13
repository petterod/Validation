package Validering;

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AddingRecordsSyslog {
	//Format for fieldnames is:
	//timestamp,hostname,app-name,message,objectnr,objecttype; 
	ArrayList<String> fieldnames = new ArrayList<String>(Arrays.asList("MINUSLONG","BOOLEAN","BOOLEAN",
	"BOOLEAN","objectnr","objecttype"));
	
	ArrayList<List<String>> pkts = new ArrayList<>();
	List<String> pkt;
	String FNAME;
	
	public AddingRecordsSyslog(String inputO, String inputA, String outputO, String outputA) throws FileNotFoundException {
		FNAME = outputO;
		ObjectGrouping og1 = new ObjectGrouping(inputO,"Syslog");
		pkts = og1.getPkts();
		addingInterRecords();
		toTextFile();
		FNAME = outputA;
		ObjectGrouping og2 = new ObjectGrouping(inputA,"Syslog");
		pkts = og2.getPkts();
		addingInterRecords();
		toTextFile();
		System.out.println(og1.getNrOfPkts() + " packets - " + og1.getHosts() + " hosts - " + og1
				.getWebPages() + " web pages");	
	}
	
	//Method for finding the first pkt from an object.
	public List<String> findingFirstPkt(ArrayList<List<String>> pkts, int i) {
		for(List<String> pkt : pkts) {
			if(pkt.get(4).equals(Integer.toString(i))) {
				return pkt;
			}
		}
		return null;
	}
	
	//Method for adding inter-records.
	public void addingInterRecords() {
		for(int i = 1; i < Integer.parseInt(pkts.get(pkts.size()-1).get(4))+1; i ++) {
			this.pkt = findingFirstPkt(pkts,i);
			for(List<String> pkt : pkts) {	
				if(Integer.parseInt(pkt.get(4)) == i) {
					addingFields(pkt);
					this.pkt = pkt;
				}else {
					continue;
				}
			}
		}
	}
	
	//Method for adding inter-records. Based on the format defined at the start, fields are compared with
	//different methods, like MINUS, BOOLEAN, etc.
	public void addingFields(List<String> pkt) {
		for(int i= 0;i < fieldnames.size();i++) {
			if(fieldnames.get(i).equals("MINUS")) {
				compareMinus(pkt,i);
			}
			else if(fieldnames.get(i).equals("MINUSLONG")) {
				compareMinusLong(pkt,i);
			}
			else if(fieldnames.get(i).equals("BOOLEAN")) {
				compareBoolean(pkt,i);
			}
			else if(fieldnames.get(i).equals("XOR")) {
				compareXOR(pkt,i);
			}
			else if(fieldnames.get(i).equals("XORIPV4")) {
				compareXORV4(pkt,i);
			}
			else if(fieldnames.get(i).equals("XORIPV6")) {
				compareXORV6(pkt,i);
			}
			else {
				continue;
			}
		}	
	}
	
	//Comparing records based on XOR.
	public void compareXOR(List<String> pkt, int i) {
		fieldnames.add(Integer.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("0");
		}
		else {
			pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(i))^Integer.parseInt(pkt.get(i)))));
		}
	}
	
	//Comparing records based on XOR for IPv4.
	public void compareXORV4(List<String> pkt, int i) {
		if(!this.pkt.get(i).equals("null") && !pkt.get(i).equals("null")) {
			fieldnames.add(Integer.toString(i));
			if(this.pkt.equals(pkt)) {
				pkt.add("0.0.0.0");
			}
			else {
				String[] t = this.pkt.get(i).split("\\.");
				String[] s = pkt.get(i).split("\\.");
				int oc1 = Integer.parseInt(t[0])^Integer.parseInt(s[0]);
				int oc2 = Integer.parseInt(t[1])^Integer.parseInt(s[1]);
				int oc3 = Integer.parseInt(t[2])^Integer.parseInt(s[2]);
				int oc4 = Integer.parseInt(t[3])^Integer.parseInt(s[3]);
				pkt.add(oc1 + "." + oc2 + "." + oc3 + "." + oc4);
			}	
		}
	}

	//Comparing records based on XOR for IPv6.
	public void compareXORV6(List<String> pkt, int i) {
		if(!this.pkt.get(i).equals("null") && !pkt.get(i).equals("null")) {	
			fieldnames.add(Integer.toString(i));
			if(this.pkt.equals(pkt)) {
				pkt.add("0:0:0:0:0:0:0:0");
			}
			else {
				String[] t = this.pkt.get(i).split("\\:");
				String[] s = pkt.get(i).split("\\:");
				String oc1 = Integer.toHexString(Integer.parseInt(t[0],16)^Integer.parseInt(s[0],16));
				String oc2 = Integer.toHexString(Integer.parseInt(t[1],16)^Integer.parseInt(s[1],16));
				String oc3 = Integer.toHexString(Integer.parseInt(t[2],16)^Integer.parseInt(s[2],16));
				String oc4 = Integer.toHexString(Integer.parseInt(t[3],16)^Integer.parseInt(s[3],16));
				String oc5 = Integer.toHexString(Integer.parseInt(t[4],16)^Integer.parseInt(s[4],16));
				String oc6 = Integer.toHexString(Integer.parseInt(t[5],16)^Integer.parseInt(s[5],16));
				String oc7 = Integer.toHexString(Integer.parseInt(t[6],16)^Integer.parseInt(s[6],16));
				String oc8 = Integer.toHexString(Integer.parseInt(t[7],16)^Integer.parseInt(s[7],16));
				pkt.add(oc1 + ":" + oc2 + ":" + oc3 + ":" + oc4 + ":" + oc5 + ":" + oc6 + ":" + oc7 + ":" + oc8);
			}	
		}
	}
	
	//Comparing records based on MINUS.
	public void compareMinus(List<String> pkt, int i) {
		fieldnames.add(Integer.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("0");
		}
		else {
			pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(i)) - Integer.parseInt(pkt.get(i)))));
		}
	}
	
	//Comparing records based on MINUS with long.
	public void compareMinusLong(List<String> pkt, int i) {
		fieldnames.add(Integer.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("0");
		}
		else {
			pkt.add(Long.toString(Math.abs(Long.parseLong(this.pkt.get(i)) - Long.parseLong(pkt.get(i)))));
		}
	}
	
	//Comparing records based on BOOLEAN.
	public void compareBoolean(List<String> pkt, int i) {
		fieldnames.add(Integer.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("true");
		}
		else {
			pkt.add(Boolean.toString((this.pkt.get(i).equals(pkt.get(i)))));
		}
	}
	
	//Method to write lines from the new log to file.
	public void toTextFile() {
		ArrayList<String> format = new ArrayList<>();
		for(List<String> pkt : pkts) {
			String samlet = "";
			for(String field : pkt) {
				samlet += field + "\t"; 
			}
			format.add(samlet);
		}
		
		try ( BufferedWriter bw = new BufferedWriter (new FileWriter (FNAME)) ) 
		{			
			for (String line : format) {
				bw.write(line + "\n");
			}
			System.out.println("Created file " + FNAME);
			bw.close ();
			
		} catch (IOException e) {
			e.printStackTrace ();
		}
	}
		
	
	public static void main(String[] args) throws FileNotFoundException {
		if (args.length !=4) {
		      System.err.println("usage: java -jar jarfile.jar InputO.dat InputA.dat IIROoutput.dat IIRAoutput\n");
		      System.exit(-1);
		    }
		else {
			AddingRecordsSyslog rs = new AddingRecordsSyslog
					(args[0],args[1],args[2],args[3]);
		}
	}
}
