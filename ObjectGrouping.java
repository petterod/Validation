package Validering;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

public class ObjectGrouping {

	ArrayList<List<String>> pkts = new ArrayList<List<String>>();
	ArrayList<String> hosts = new ArrayList<String>();
	ArrayList<String> webPages = new ArrayList<String>();
	
	public ObjectGrouping(String pathname,String type) throws FileNotFoundException{
		Scanner s = new Scanner(new File(pathname));
		while(s.hasNextLine()) {	
			pkts.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		groupObjects(type);
		assignObjectnr(checkType(type),type);
	}
	
	//Checks which log type is selected and returns the field index of Source IP Address in this log.
	public int checkType(String type) {
		if(type.equals("IPv4")) {
			return 14;
		}
		else if(type.equals("IPv6")) {
			return 7;
		}
		else if(type.equals("Netflow")) {
			return 4;
		}
		else if(type.equals("Webserver")) {
			return 0;
		}
		else if(type.equals("Syslog")) {
			return 2;
		}
		else {
			return 99;
		}
	}
	
	//Groups objects as either hosts or web pages, with a specific index depending on the type.
	public void groupObjects(String type) {
		if(type.equals("IPv4")) {
			groupWebPageObjects(14,17);
			groupHostObjects(14);
		}
		else if(type.equals("IPv6")) {
			groupWebPageObjects(7,10);
			groupHostObjects(7);
		}
		else if(type.equals("Netflow")) {
			groupWebPageObjects(4,7);
			groupHostObjects(4);
		}
		else if(type.equals("Webserver")) {
			groupHostObjects(0);
		}
		else if(type.equals("Syslog")) {
			groupHostObjects(2);
		}
	}
	
	//Groups a packet as a web page if the criterias are met.
	public void groupWebPageObjects(int addr, int port) {
		for(List<String> pkt : pkts) {
			if((!webPages.contains(pkt.get(addr))) && (pkt.get(port).equals("80") || pkt.get(port).equals("443"))) {
				webPages.add(pkt.get(addr));
			}

		}
	}
	
	//Groups a packet as a host if the criterias are met.
	public void groupHostObjects(int addr) {
		for(List<String> pkt : pkts) {
			if(!hosts.contains(pkt.get(addr)) && (!webPages.contains(pkt.get(addr)))) {
				hosts.add(pkt.get(addr));
			}

		}
	}
	
	//Assings object number to the packets grouped as either web page or host. All packets with equal
	//Source IP Address are grouped as one object, and thus have the same object number. A sort on the
	//object number is performed in the end, based on which type the log is.
	public void assignObjectnr(int addr, String type) {
		int i = 1;
		for(String host : hosts) {
			for(List<String> pkt : pkts) {
				if(pkt.get(addr).equals(host)) {
					pkt.add(Integer.toString(i));
					pkt.add("host");
				}
			}
			i++;
		}
		for(String webPage : webPages) {
			for(List<String> pkt : pkts) {
				if(pkt.get(addr).equals(webPage)) {
					pkt.add(Integer.toString(i));
					pkt.add("webPage");
				}
			}
			i++;
		}
		if(type.equals("IPv4")) {
			Collections.sort(pkts,new ListComparatorIPv4());
		}
		else if(type.equals("IPv6")) {
			Collections.sort(pkts,new ListComparatorIPv6());
		}
		else if(type.equals("Netflow")) {
			Collections.sort(pkts,new ListComparatorNetFlow());
		}
		else if(type.equals("Webserver")) {
			Collections.sort(pkts,new ListComparatorWebserver());
		}
		else if(type.equals("Syslog")) {
			Collections.sort(pkts,new ListComparatorSyslog());
		}	
	}
	
	public int getNrOfPkts() {
		return pkts.size();
	}
		
	public int getHosts() {
		return hosts.size();
	}
	
	public int getWebPages() {
		return webPages.size();
	}
	
	public ArrayList<List<String>> getPkts() {
		return pkts;
	}
}
