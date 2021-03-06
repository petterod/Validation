package Validering;

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AddingRecordsIPv4 {
	//Format for fieldnames is:
	//version,timestamp,internetHeaderLength,dscp,ecn,totalLength,identification,reservedSet,dontFragment,moreFragments,
	//fragmentOffset,timeToLive,protocol,headerChecksum,srcipv4,dstipv4,srcport,dstport,seqNr,ackNr,dataOffset,reserved,
	//isNS,isCWR,isECE,isURG,isACK,isPSH,isRST,isSYN,isFIN,windowSize,checksum,urgentPointer,length,objectnr,objecttype; 
	ArrayList<String> fieldnames = new ArrayList<String>(Arrays.asList("no need to compare version","MINUSLONG",
	"MINUS","XOR","XOR","MINUS","MINUS","BOOLEAN","BOOLEAN","BOOLEAN","MINUS","MINUS","BOOLEAN","BOOLEAN","XORIPV4",
	"XORIPV4","MINUS","MINUS","MINUSLONG","MINUSLONG","MINUS","XOR","BOOLEAN","BOOLEAN","BOOLEAN","BOOLEAN","BOOLEAN",
	"BOOLEAN","BOOLEAN","BOOLEAN","BOOLEAN","MINUS","BOOLEAN","MINUS","MINUS","objectnr","objecttype"));
	
	ArrayList<List<String>> pkts = new ArrayList<>();
	List<String> pkt;
	String FNAME;
	
	public AddingRecordsIPv4(String inputO, String inputA, String outputO, String outputA) throws FileNotFoundException {
		FNAME = outputO;
		ObjectGrouping og1 = new ObjectGrouping(inputO,"IPv4");
		pkts = og1.getPkts();
		addingInterRecords();
		toTextFile();
		FNAME = outputA;
		ObjectGrouping og2 = new ObjectGrouping(inputA,"IPv4");
		pkts = og2.getPkts();
		addingInterRecords();
		toTextFile();
		System.out.println(og1.getNrOfPkts() + " packets - " + og1.getHosts() + " hosts - " + og1
				.getWebPages() + " web pages");
	}
	
	//Method for finding the first pkt from an object.
	public List<String> findingFirstPkt(ArrayList<List<String>> pkts, int i) {
		for(List<String> pkt : pkts) {
			if(pkt.get(35).equals(Integer.toString(i))) {
				return pkt;
			}
		}
		return null;
	}
	
	//Method for adding inter- and intra-records.
	public void addingInterRecords() {
		for(int i = 1; i < Integer.parseInt(pkts.get(pkts.size()-1).get(35))+1; i ++) {
			this.pkt = findingFirstPkt(pkts,i);
			for(List<String> pkt : pkts) {	
				if(Integer.parseInt(pkt.get(35)) == i) {
					addingFields(pkt);
					addingIntraRecords(pkt);
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
				compareMinusLong(pkt, i);
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
	
	//Method that adds intra-records for IP addresses and ports.
	public void addingIntraRecords(List<String> pkt) {
		String[] s = pkt.get(14).split("\\.");
		String[] t = pkt.get(15).split("\\.");
		String[] u = pkt.get(50).split("\\.");
		String[] v = pkt.get(51).split("\\.");
		
		int st_oc1 = Integer.parseInt(s[0])^Integer.parseInt(t[0]);
		int st_oc2 = Integer.parseInt(s[1])^Integer.parseInt(t[1]);
		int st_oc3 = Integer.parseInt(s[2])^Integer.parseInt(t[2]);
		int st_oc4 = Integer.parseInt(s[3])^Integer.parseInt(t[3]);
		
		int su_oc1 = Integer.parseInt(s[0])^Integer.parseInt(u[0]);
		int su_oc2 = Integer.parseInt(s[1])^Integer.parseInt(u[1]);
		int su_oc3 = Integer.parseInt(s[2])^Integer.parseInt(u[2]);
		int su_oc4 = Integer.parseInt(s[3])^Integer.parseInt(u[3]);
			
		int sv_oc1 = Integer.parseInt(s[0])^Integer.parseInt(v[0]);
		int sv_oc2 = Integer.parseInt(s[1])^Integer.parseInt(v[1]);
		int sv_oc3 = Integer.parseInt(s[2])^Integer.parseInt(v[2]);
		int sv_oc4 = Integer.parseInt(s[3])^Integer.parseInt(v[3]);
		
		int tu_oc1 = Integer.parseInt(t[0])^Integer.parseInt(u[0]);
		int tu_oc2 = Integer.parseInt(t[1])^Integer.parseInt(u[1]);
		int tu_oc3 = Integer.parseInt(t[2])^Integer.parseInt(u[2]);
		int tu_oc4 = Integer.parseInt(t[3])^Integer.parseInt(u[3]);
		
		int tv_oc1 = Integer.parseInt(t[0])^Integer.parseInt(v[0]);
		int tv_oc2 = Integer.parseInt(t[1])^Integer.parseInt(v[1]);
		int tv_oc3 = Integer.parseInt(t[2])^Integer.parseInt(v[2]);
		int tv_oc4 = Integer.parseInt(t[3])^Integer.parseInt(v[3]);
		
		int uv_oc1 = Integer.parseInt(u[0])^Integer.parseInt(v[0]);
		int uv_oc2 = Integer.parseInt(u[1])^Integer.parseInt(v[1]);
		int uv_oc3 = Integer.parseInt(u[2])^Integer.parseInt(v[2]);
		int uv_oc4 = Integer.parseInt(u[3])^Integer.parseInt(v[3]);
			
		fieldnames.add("IntraRecordIPv4");
		fieldnames.add("IntraRecordIPv4");
		fieldnames.add("IntraRecordIPv4");
		fieldnames.add("IntraRecordIPv4");
		fieldnames.add("IntraRecordIPv4");
		fieldnames.add("IntraRecordIPv4");

		pkt.add(st_oc1 + "." + st_oc2 + "." + st_oc3 + "." + st_oc4);
		pkt.add(su_oc1 + "." + su_oc2 + "." + su_oc3 + "." + su_oc4);
		pkt.add(sv_oc1 + "." + sv_oc2 + "." + sv_oc3 + "." + sv_oc4);
		pkt.add(tu_oc1 + "." + tu_oc2 + "." + tu_oc3 + "." + tu_oc4);
		pkt.add(tv_oc1 + "." + tv_oc2 + "." + tv_oc3 + "." + tv_oc4);
		pkt.add(uv_oc1 + "." + uv_oc2 + "." + uv_oc3 + "." + uv_oc4);
				
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(pkt.get(16)) - Integer.parseInt(pkt.get(17)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(pkt.get(16)) - Integer.parseInt(pkt.get(52)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(pkt.get(16)) - Integer.parseInt(pkt.get(53)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(pkt.get(17)) - Integer.parseInt(pkt.get(52)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(pkt.get(17)) - Integer.parseInt(pkt.get(53)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(pkt.get(52)) - Integer.parseInt(pkt.get(53)))));
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
		      System.err.println("Usage: java -jar jarfile.jar InputO.dat InputA.dat IIROoutput.dat IIRAoutput\n");
		      System.exit(-1);
		    }
		else {
			AddingRecordsIPv4 rs = new AddingRecordsIPv4(args[0],args[1],args[2],args[3]);
		}
	}
}
