package Validering;

import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class AddingRecordsNetFlow2 {
	//Format for fieldnames er:
	//starttime,endtime,duration,protocol,srcaddress,dstaddress,srcport,dstport,srcas,dstas,inputinterfacenum,
	//outputinterfacenum,packets,bytes,flows,flags,tos,bytespersecond,packetspersecond,bytesperpacket,
	//objectnr,objecttype;
	ArrayList<String> fieldnames = new ArrayList<String>(Arrays.asList("MINUSLONG","MINUSLONG","MINUSDOUBLE",
			"BOOLEAN","CHECKIP","CHECKIP","MINUS","MINUS","MINUS","MINUS","MINUS","MINUS","MINUS","MINUSLONG",
			"MINUS","BOOLEAN","MINUS","MINUSLONG","MINUS","MINUS","objectnr","objecttype"));
	
	ArrayList<List<String>> pkts = new ArrayList<>();
	List<String> pkt;
	String FNAME;
	
	public AddingRecordsNetFlow2(String inputO, String inputA, String outputO, String outputA) throws FileNotFoundException {
		FNAME = outputO;
		ObjectGrouping og1 = new ObjectGrouping(inputO,"Netflow");
		pkts = og1.getPkts();
		addingInterRecords();
		toTextFile();
		FNAME = outputA;
		ObjectGrouping og2 = new ObjectGrouping(inputA,"Netflow");
		pkts = og2.getPkts();
		addingInterRecords();
		toTextFile();
	}
	
	public void getFieldnames() {
		int j = 0;
		for(String f : fieldnames) {
			System.out.println(j + " " + f);
			j++;
		}
	}
	
	//Method for finding the first pkt from an object
	public List<String> findingFirstPkt(ArrayList<List<String>> pkts, int i) {
		for(List<String> pkt : pkts) {
			if(pkt.get(20).equals(Integer.toString(i))) {
				return pkt;
			}
		}
		return null;
	}
	
	public void addingInterRecords() {
		for(int i = 1; i < Integer.parseInt(pkts.get(pkts.size()-1).get(20))+1; i ++) {
			this.pkt = findingFirstPkt(pkts,i);
			for(List<String> pkt : pkts) {	
				if(Integer.parseInt(pkt.get(20)) == i) {
					addingFields(pkt);
					addingIntraRecords(pkt);
					this.pkt = pkt;
				}else {
					continue;
				}
			}
		}
	}
	
	public void addingFields(List<String> pkt) {
		for(int i= 0;i < fieldnames.size();i++) {
			if(fieldnames.get(i).equals("MINUS")) {
				compareMinus(pkt,i);
			}
			else if(fieldnames.get(i).equals("CHECKIP")) {
				checkIP(pkt,i);
			}
			else if(fieldnames.get(i).equals("MINUSDOUBLE")) {
				compareMinusDouble(pkt, i);
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
	
	public void checkIP(List<String> pkt, int i) {
		if(pkt.get(i).contains(".")) {
			compareXORV4(pkt, i);
		}
		else if(pkt.get(i).contains(":")) {
			compareXORV6(pkt,i);
		}
	}
	
	public void compareXOR(List<String> pkt, int i) {
		fieldnames.add(Integer.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("0");
		}
		else {
			pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(i))^Integer.parseInt(pkt.get(i)))));
		}
	}
	
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
	
	public void compareMinus(List<String> pkt, int i) {
		fieldnames.add(Integer.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("0");
		}
		else {
			pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(i)) - Integer.parseInt(pkt.get(i)))));
		}
	}
	
	public void compareMinusDouble(List<String> pkt, int i) {
		fieldnames.add(Double.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("0");
		}
		else {
			pkt.add(Double.toString(Math.abs(Double.parseDouble(this.pkt.get(i)) - Double.parseDouble(pkt.get(i)))));
		}
	}
	
	public void compareMinusLong(List<String> pkt, int i) {
		fieldnames.add(Integer.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("0");
		}
		else {
			pkt.add(Long.toString(Math.abs(Long.parseLong(this.pkt.get(i)) - Long.parseLong(pkt.get(i)))));
		}
	}
	
	public void compareBoolean(List<String> pkt, int i) {
		fieldnames.add(Integer.toString(i));
		if(this.pkt.equals(pkt)){
			pkt.add("true");
		}
		else {
			pkt.add(Boolean.toString((this.pkt.get(i).equals(pkt.get(i)))));
		}
	}
	
	
	public void addingIntraRecords(List<String> pkt) {
		if(pkt.get(4).contains(".")) {
			String[] s = pkt.get(4).split("\\.");
			String[] t = pkt.get(5).split("\\.");
			String[] u = pkt.get(26).split("\\.");
			String[] v = pkt.get(27).split("\\.");
			
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
		}
	
		else if(pkt.get(3).contains(":")) {
			String[] s = pkt.get(4).split(":");
			String[] t = pkt.get(5).split(":");
			String[] u = pkt.get(26).split(":");
			String[] v = pkt.get(27).split(":");
			
			String st_oc1 = Integer.toHexString(Integer.parseInt(s[0],16)^Integer.parseInt(t[0],16));
			String st_oc2 = Integer.toHexString(Integer.parseInt(s[1],16)^Integer.parseInt(t[1],16));
			String st_oc3 = Integer.toHexString(Integer.parseInt(s[2],16)^Integer.parseInt(t[2],16));
			String st_oc4 = Integer.toHexString(Integer.parseInt(s[3],16)^Integer.parseInt(t[3],16));
			String st_oc5 = Integer.toHexString(Integer.parseInt(s[4],16)^Integer.parseInt(t[4],16));
			String st_oc6 = Integer.toHexString(Integer.parseInt(s[5],16)^Integer.parseInt(t[5],16));
			String st_oc7 = Integer.toHexString(Integer.parseInt(s[6],16)^Integer.parseInt(t[6],16));
			String st_oc8 = Integer.toHexString(Integer.parseInt(s[7],16)^Integer.parseInt(t[7],16));
			
			String su_oc1 = Integer.toHexString(Integer.parseInt(s[0],16)^Integer.parseInt(u[0],16));
			String su_oc2 = Integer.toHexString(Integer.parseInt(s[1],16)^Integer.parseInt(u[1],16));
			String su_oc3 = Integer.toHexString(Integer.parseInt(s[2],16)^Integer.parseInt(u[2],16));
			String su_oc4 = Integer.toHexString(Integer.parseInt(s[3],16)^Integer.parseInt(u[3],16));
			String su_oc5 = Integer.toHexString(Integer.parseInt(s[4],16)^Integer.parseInt(u[4],16));
			String su_oc6 = Integer.toHexString(Integer.parseInt(s[5],16)^Integer.parseInt(u[5],16));
			String su_oc7 = Integer.toHexString(Integer.parseInt(s[6],16)^Integer.parseInt(u[6],16));
			String su_oc8 = Integer.toHexString(Integer.parseInt(s[7],16)^Integer.parseInt(u[7],16));
			
			String sv_oc1 = Integer.toHexString(Integer.parseInt(s[0],16)^Integer.parseInt(v[0],16));
			String sv_oc2 = Integer.toHexString(Integer.parseInt(s[1],16)^Integer.parseInt(v[1],16));
			String sv_oc3 = Integer.toHexString(Integer.parseInt(s[2],16)^Integer.parseInt(v[2],16));
			String sv_oc4 = Integer.toHexString(Integer.parseInt(s[3],16)^Integer.parseInt(v[3],16));
			String sv_oc5 = Integer.toHexString(Integer.parseInt(s[4],16)^Integer.parseInt(v[4],16));
			String sv_oc6 = Integer.toHexString(Integer.parseInt(s[5],16)^Integer.parseInt(v[5],16));
			String sv_oc7 = Integer.toHexString(Integer.parseInt(s[6],16)^Integer.parseInt(v[6],16));
			String sv_oc8 = Integer.toHexString(Integer.parseInt(s[7],16)^Integer.parseInt(v[7],16));
			
			String tu_oc1 = Integer.toHexString(Integer.parseInt(t[0],16)^Integer.parseInt(u[0],16));
			String tu_oc2 = Integer.toHexString(Integer.parseInt(t[1],16)^Integer.parseInt(u[1],16));
			String tu_oc3 = Integer.toHexString(Integer.parseInt(t[2],16)^Integer.parseInt(u[2],16));
			String tu_oc4 = Integer.toHexString(Integer.parseInt(t[3],16)^Integer.parseInt(u[3],16));
			String tu_oc5 = Integer.toHexString(Integer.parseInt(t[4],16)^Integer.parseInt(u[4],16));
			String tu_oc6 = Integer.toHexString(Integer.parseInt(t[5],16)^Integer.parseInt(u[5],16));
			String tu_oc7 = Integer.toHexString(Integer.parseInt(t[6],16)^Integer.parseInt(u[6],16));
			String tu_oc8 = Integer.toHexString(Integer.parseInt(t[7],16)^Integer.parseInt(u[7],16));
			
			String tv_oc1 = Integer.toHexString(Integer.parseInt(t[0],16)^Integer.parseInt(v[0],16));
			String tv_oc2 = Integer.toHexString(Integer.parseInt(t[1],16)^Integer.parseInt(v[1],16));
			String tv_oc3 = Integer.toHexString(Integer.parseInt(t[2],16)^Integer.parseInt(v[2],16));
			String tv_oc4 = Integer.toHexString(Integer.parseInt(t[3],16)^Integer.parseInt(v[3],16));
			String tv_oc5 = Integer.toHexString(Integer.parseInt(t[4],16)^Integer.parseInt(v[4],16));
			String tv_oc6 = Integer.toHexString(Integer.parseInt(t[5],16)^Integer.parseInt(v[5],16));
			String tv_oc7 = Integer.toHexString(Integer.parseInt(t[6],16)^Integer.parseInt(v[6],16));
			String tv_oc8 = Integer.toHexString(Integer.parseInt(t[7],16)^Integer.parseInt(v[7],16));
			
			String uv_oc1 = Integer.toHexString(Integer.parseInt(u[0],16)^Integer.parseInt(v[0],16));
			String uv_oc2 = Integer.toHexString(Integer.parseInt(u[1],16)^Integer.parseInt(v[1],16));
			String uv_oc3 = Integer.toHexString(Integer.parseInt(u[2],16)^Integer.parseInt(v[2],16));
			String uv_oc4 = Integer.toHexString(Integer.parseInt(u[3],16)^Integer.parseInt(v[3],16));
			String uv_oc5 = Integer.toHexString(Integer.parseInt(u[4],16)^Integer.parseInt(v[4],16));
			String uv_oc6 = Integer.toHexString(Integer.parseInt(u[5],16)^Integer.parseInt(v[5],16));
			String uv_oc7 = Integer.toHexString(Integer.parseInt(u[6],16)^Integer.parseInt(v[6],16));
			String uv_oc8 = Integer.toHexString(Integer.parseInt(u[7],16)^Integer.parseInt(v[7],16));
			
			fieldnames.add("IntraRecordIPv6");
			fieldnames.add("IntraRecordIPv6");
			fieldnames.add("IntraRecordIPv6");
			fieldnames.add("IntraRecordIPv6");
			fieldnames.add("IntraRecordIPv6");
			fieldnames.add("IntraRecordIPv6");
	
			pkt.add(st_oc1 + ":" + st_oc2 + ":" + st_oc3 + ":" + st_oc4 + ":" + st_oc5 + ":" + st_oc6 + ":" + st_oc7 + ":" + st_oc8);
			pkt.add(su_oc1 + ":" + su_oc2 + ":" + su_oc3 + ":" + su_oc4 + ":" + su_oc5 + ":" + su_oc6 + ":" + su_oc7 + ":" + su_oc8);
			pkt.add(sv_oc1 + ":" + sv_oc2 + ":" + sv_oc3 + ":" + sv_oc4 + ":" + sv_oc5 + ":" + sv_oc6 + ":" + sv_oc7 + ":" + sv_oc8);
			pkt.add(tu_oc1 + ":" + tu_oc2 + ":" + tu_oc3 + ":" + tu_oc4 + ":" + tu_oc5 + ":" + tu_oc6 + ":" + tu_oc7 + ":" + tu_oc8);
			pkt.add(tv_oc1 + ":" + tv_oc2 + ":" + tv_oc3 + ":" + tv_oc4 + ":" + tv_oc5 + ":" + tv_oc6 + ":" + tv_oc7 + ":" + tv_oc8);
			pkt.add(uv_oc1 + ":" + uv_oc2 + ":" + uv_oc3 + ":" + uv_oc4 + ":" + uv_oc5 + ":" + uv_oc6 + ":" + uv_oc7 + ":" + uv_oc8);
			
		}
				
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		fieldnames.add("IntraRecordPort");
		
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(6)) - Integer.parseInt(pkt.get(7)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(6)) - Integer.parseInt(pkt.get(28)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(6)) - Integer.parseInt(pkt.get(29)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(7)) - Integer.parseInt(pkt.get(28)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(7)) - Integer.parseInt(pkt.get(29)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(28)) - Integer.parseInt(pkt.get(29)))));
		
		fieldnames.add("IntraRecordAS");
		fieldnames.add("IntraRecordAS");
		fieldnames.add("IntraRecordAS");
		fieldnames.add("IntraRecordAS");
		fieldnames.add("IntraRecordAS");
		fieldnames.add("IntraRecordAS");
		
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(8)) - Integer.parseInt(pkt.get(9)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(8)) - Integer.parseInt(pkt.get(30)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(8)) - Integer.parseInt(pkt.get(31)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(9)) - Integer.parseInt(pkt.get(30)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(9)) - Integer.parseInt(pkt.get(31)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(30)) - Integer.parseInt(pkt.get(31)))));
		
		fieldnames.add("IntraRecordInterface");
		fieldnames.add("IntraRecordInterface");
		fieldnames.add("IntraRecordInterface");
		fieldnames.add("IntraRecordInterface");
		fieldnames.add("IntraRecordInterface");
		fieldnames.add("IntraRecordInterface");
		
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(10)) - Integer.parseInt(pkt.get(11)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(10)) - Integer.parseInt(pkt.get(32)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(10)) - Integer.parseInt(pkt.get(33)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(11)) - Integer.parseInt(pkt.get(32)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(11)) - Integer.parseInt(pkt.get(33)))));
		pkt.add(Integer.toString(Math.abs(Integer.parseInt(this.pkt.get(32)) - Integer.parseInt(pkt.get(33)))));
	}
	
	public void outprint() {
		for(List<String> pkt : pkts) {
			System.out.println(pkt.get(2));
		}
	}
	
	
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
				//System.out.println(line);
				bw.write(line + "\n");
			}
			System.out.println("Created file " + FNAME);
			bw.close ();
			
		} catch (IOException e) {
			e.printStackTrace ();
		}
	}
		
	
	public static void main(String[] args) throws FileNotFoundException {
//		AddingRecordsNetFlow ar = new AddingRecordsNetFlow(
//		"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Netflow\\O2-Netflow.dat",
//		"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Netflow\\A2-Netflow.dat",
//		"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Netflow\\IIRO2-Netflow.dat",
//		"C:\\Users\\Petter\\Documents\\Master\\Datasets\\Netflow\\IIRA2-Netflow.dat");
		if (args.length !=4) {
			System.err.println("usage: java -jar jarfile.jar InputO.dat InputA.dat IIROoutput.dat IIRAoutput\n");
			System.exit(-1);
		}
		else {
			AddingRecordsNetFlow2 rs = new AddingRecordsNetFlow2(args[0],args[1],args[2],args[3]);
		}
	}
}
