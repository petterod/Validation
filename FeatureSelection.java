package Validering;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;

public class FeatureSelection {
	
	ArrayList<List<String>> original = new ArrayList<List<String>>();
	ArrayList<List<String>> anonymized = new ArrayList<List<String>>();
	Entropy entropy;
	ArrayList<String> overThreshold;
	ArrayList<String> combined;
	ArrayList<List<String>> groupCollection;
	List<String> pktsAdded;
	
	
	public FeatureSelection(String type, String original, String anonymized, String outputO, String outputA) throws FileNotFoundException{
		Scanner s = new Scanner(new File(original));
		Scanner t = new Scanner(new File(anonymized));
		while(s.hasNextLine()) {	
			this.original.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		s.close();
		while(t.hasNextLine()) {	
			this.anonymized.add(new ArrayList<String>(Arrays.asList(t.nextLine().split("\t"))));
		}
		t.close();
		checkType(type, outputO, outputA);		
	}
	
	//Checks which log type is selected, and performs feature selection for this log type
	public void checkType(String type, String outputO, String outputA) {
		if(type.equalsIgnoreCase("ipv4")) {
			forEveryObject(this.original, outputO,35,36);
			forEveryObject(this.anonymized, outputA,35,36);
		}
		else if(type.equalsIgnoreCase("ipv6")) {
			forEveryObject(this.original, outputO,28,29);
			forEveryObject(this.anonymized, outputA,28,29);
		}
		else if(type.equalsIgnoreCase("netflow")) {
			forEveryObject(this.original, outputO,20,21);
			forEveryObject(this.anonymized, outputA,20,21);
		}
		else if(type.equalsIgnoreCase("webserver")) {
			forEveryObject(this.original, outputO,9,10);
			forEveryObject(this.anonymized, outputA,9,10);
		}
		else if(type.equalsIgnoreCase("syslog")) {
			forEveryObject(this.original, outputO,4,5);
			forEveryObject(this.anonymized, outputA,4,5);
		}		
	}
	
	//Method that makes a list of the field specified in the argument fieldIndex. 
	public ArrayList<String> getField(ArrayList<List<String>> pkts, int fieldIndex, int objectnr, int nrIndex) {
		ArrayList<String> res = new ArrayList<String>();
		for(List<String> pkt : pkts) {
			if(pkt.get(nrIndex).equals(Integer.toString(objectnr))) {
				res.add(pkt.get(fieldIndex));
			}
		}
		return res;	
	}
	
	//Method that compares two fields and checks if their normalized mutual information is more than 0.99. 
	//If it is, then the fields are added to the overThreshold list.
	public void selectingObject(ArrayList<List<String>> settype,int objectnr, int nrIndex, int typeIndex) {
		overThreshold = new ArrayList<String>();
		for(int i = 0; i < settype.get(0).size();i++) {
			ArrayList<String> columnI = getField(settype,i,objectnr,nrIndex);
			for(int j = 0; j < settype.get(0).size();j++) {
				if(i != j && !(i == nrIndex || j == nrIndex) && !(i == typeIndex || j == typeIndex)) {
					ArrayList<String> columnJ = getField(settype,j,objectnr,nrIndex);
					entropy = new Entropy(columnI,columnJ);
					if(!overThreshold.contains(j + ";" + i) && entropy.normalizedMutualInformation() > 0.99) {
						overThreshold.add(i + ";" + j);
					}
				}
			}
		}
	}
	
	//Method that initiates groupFields() with the strings from overThreshold.	
	public void inputSimilarFields() {
		combined = new ArrayList<String>();
		for(String x : overThreshold) {
			groupFields(x);
		}
	}
	
	//Method that combines fields from overThreshold into a group containing all fields that share one field.
	public void groupFields(String combined) {
		String i = combined.split("\\;")[0];
		String j = combined.split("\\;")[1];
		String iCombined = combined;
		for(String comb : overThreshold) {
			if(!comb.equals(combined)) {
				String x = comb.split("\\;")[0];
				String y = comb.split("\\;")[1];
				if((x.equals(i) || x.equals(j)) && !iCombined.contains(y)) {
					iCombined += ";" + y;
				}
			}
		}
		this.combined.add(iCombined);
	}
	
	//Method that makes groups of the fields that both have a high normalized mutual information and share one field with 
	//another group. 
	public ArrayList<List<String>> sharingFields() {
		groupCollection = new ArrayList<List<String>>();
		if(!combined.isEmpty()) {
			ArrayList<String> combinedFields = new ArrayList<String>(Arrays.asList(combined.get(0)));
			ArrayList<List<String>> temp = new ArrayList<>();
			for(String group1 : combined){
				if(combinedFields.contains(group1)) {
					List<String> group1fields = new ArrayList<String>(Arrays.asList(group1.split(";")));
					for(String group2 : combined) {
						if(!group1.equals(group2)) {
							List<String> group2fields = new ArrayList<String>(Arrays.asList(group2.split(";")));
							if(!Collections.disjoint(group1fields, group2fields)) {
								List<String> notpresent = new ArrayList<String>(group2fields);
								notpresent.removeAll(group1fields);
								group1fields.addAll(notpresent);
								combinedFields.add(group1);
							}
							else {
								combinedFields.add(group1);
								combinedFields.add(group2);
							}
						}
					}
					temp.add(group1fields);
				}
				else {
				}
			}
			for(List<String> group : temp) {
				groupCollection.add(group);
			}
			return groupCollection;
		}
		else {
			return groupCollection;
			}
	}
	
	//Method to merge fields from the groups into the temporary string mergedString, which will further be 
	//used to make the final packet with feature selection added. Used in makeFeatureDataSet().
	public String mergeGroups(List<String> group, List<String> pkt) {
		String mergedString = "";
		for(int i = 0; i<group.size(); i++) {
			mergedString += pkt.get(Integer.parseInt(group.get(i)));
		}
		return mergedString;
	}
	
	//Method to make the final packets with feature selection added.
	public List<String> makeFeatureDataSet(ArrayList<List<String>> settype, int objectnr, int nrIndex, int typeIndex) {
		pktsAdded = new ArrayList<String>();
		ArrayList<Integer> usedFields = new ArrayList<>();
		for(List<String> group : groupCollection) {
			for(String fieldNr : group) {
				usedFields.add(Integer.parseInt(fieldNr));
			}
		}
		for(List<String> pkt : settype) {
			if(pkt.get(nrIndex).equals(Integer.toString(objectnr))) {
				ArrayList<List<String>> usedGroups = new ArrayList<>();
				String mergedString = pkt.get(nrIndex) + "\t" + pkt.get(typeIndex) + "\t";
				usedFields.add(nrIndex);
				usedFields.add(typeIndex);
				for(int i = 0; i < settype.get(0).size(); i ++) {
					if(!usedFields.contains(i)) {
						mergedString += pkt.get(i) + "\t";
					}
					else {
						for(List<String> gruppe :groupCollection) {
							for(String nr : gruppe) {
								if(i == Integer.parseInt(nr) && !usedGroups.contains(gruppe)) {
									mergedString += mergeGroups(gruppe,pkt) + "\t";
									usedGroups.add(gruppe);
									usedFields.add(i);
								}
							}
						}
					}
				}
			pktsAdded.add(mergedString + "\n");
			}
		}
		return pktsAdded;
	}
	
	//Method for finding feature selection for each object, and then storing the 
	//results in a ArrayList<List<String>>.	
	public void forEveryObject(ArrayList<List<String>> settype,String FNAME, int nrIndex, int typeIndex) {
		ArrayList<List<String>> objectsAdded = new ArrayList<List<String>>();
		for(int i = 1; i < Integer.parseInt(settype.get(settype.size()-1).get(nrIndex))+1; i++) {
			selectingObject(settype,i,nrIndex,typeIndex);
			inputSimilarFields();
			sharingFields();
			objectsAdded.add(makeFeatureDataSet(settype,i,nrIndex,typeIndex));
		}
		toTextFile(objectsAdded,FNAME);
	}
	
	//Method to write lines from the new log to text file.
	public void toTextFile(ArrayList<List<String>> objectsAdded, String FNAME) {
		ArrayList<String> format = new ArrayList<>();
		for(List<String> pkt : objectsAdded) {
			String samlet = "";
			for(String field : pkt) {
				samlet += field; 
			}
			format.add(samlet);
		}
		
		try ( BufferedWriter bw = new BufferedWriter (new FileWriter (FNAME)) ) 
		{
			for (String line : format) {
				bw.write(line);
			}
			System.out.println("Created file " + FNAME);
			bw.close ();
			
		} catch (IOException e) {
			e.printStackTrace ();
		}
	}
	
	public static void main(String[] args) throws FileNotFoundException {
		if (args.length !=5) {
		      System.err.println("usage: java -jar jarfile.jar logtype originalInput.dat anonymizedInput.dat"
		      		+ " originalOutput.dat anonymizedOutput.dat\nThe logtype must either be IPv4, IPv6, Netflow, Webserver or Syslog.");
		      System.exit(-1);
		    }
		else {
			FeatureSelection fs = new FeatureSelection(args[0],args[1],args[2],args[3],args[4]);
		}
	}
}
