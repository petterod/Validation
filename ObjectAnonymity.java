package Validering;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

public class ObjectAnonymity {
	
	private ArrayList<List<String>> original = new ArrayList<List<String>>();
	private ArrayList<List<String>> anonymized = new ArrayList<List<String>>();
	private Entropy entropyCalc;
	private HashMap<String, Double> fieldEntropy;
	private HashMap<String, Integer> objectSizeA;
	private ArrayList<Integer> hosts = new ArrayList<Integer>();
	private ArrayList<Integer> webpages = new ArrayList<Integer>();
	private ArrayList<Integer> mappedAnonymizedHost = new ArrayList<Integer>();
	private ArrayList<Integer> mappedOriginalHost = new ArrayList<Integer>();
	private ArrayList<Integer> mappedAnonymizedWebpage = new ArrayList<Integer>();
	private ArrayList<Integer> mappedOriginalWebpage = new ArrayList<Integer>();
	
	public ObjectAnonymity(String original, String anonymized) throws FileNotFoundException {
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
		getObjectSize();
		getTypes(true);
		getTypes(false);
	}
	
	public void setMapped(int anonymizedObject, int unanonymizedObject, String objectType) {
		if(objectType.equals("host")) {
			mappedAnonymizedHost.add(anonymizedObject);
			mappedOriginalHost.add(unanonymizedObject);
		}
		else {
			mappedAnonymizedWebpage.add(anonymizedObject);
			mappedOriginalWebpage.add(unanonymizedObject);
		}
	}
	
	public ArrayList<Integer> getMappedAnonymizedHost(){
		return mappedAnonymizedHost;
	}
	
	public ArrayList<Integer> getMappedOriginalHost(){
		return mappedOriginalHost;
	}
	
	public ArrayList<Integer> getMappedAnonymizedWebpage(){
		return mappedAnonymizedWebpage;
	}
	
	public ArrayList<Integer> getMappedOriginalWebpage(){
		return mappedOriginalWebpage;
	}
	
	public int getNrOfObjects(){
		return Integer.parseInt(anonymized.get(anonymized.size()-1).get(0));
	}
	
	public int getNrOfObjectTypes(String objectType) {
		ArrayList<String> objects = new ArrayList<String>();
		for(List<String> x : anonymized) {
			if(x.get(1).equals(objectType) && !objects.contains(x.get(0))) {
				objects.add(x.get(0));
			}
		}
		return objects.size();
	}
	
	//Method for getting the size, that is, number of features, for each object.
	public void getObjectSize() {
		objectSizeA = new HashMap<String, Integer>();
		for(int i = 1; i < Integer.parseInt(anonymized.get(anonymized.size()-1).get(0))+1; i++) {
			for(List<String> x : anonymized) {
				if(Integer.parseInt(x.get(0)) == i) {
					objectSizeA.put("" + i, x.size());
					continue;
				}
			}
		}
	}
	
	public HashMap<String, Integer> getAllObjectSizes(){
		return objectSizeA;
	}
	
	//Method for sorting which objects are hosts and which are webpages.
	public void getTypes(boolean isHost) {
		if(isHost) {
			for(List<String> x : anonymized) {
				if(x.get(1).equals("host") && !hosts.contains(Integer.parseInt(x.get(0)))) {
					hosts.add(Integer.parseInt(x.get(0)));
				}
			}
		}
		else {
			for(List<String> x : anonymized) {
				if(x.get(1).equals("webPage") && !webpages.contains(Integer.parseInt(x.get(0)))) {
					webpages.add(Integer.parseInt(x.get(0)));
				}
			}
		}
	}
	
	//Method for checking if an object is host or webpage.
	public boolean doesItContain(int j, String objectType) {
		if(objectType.equals("host")) {
			if(hosts.contains(j)) {
				return true;
			}
			else {
				return false;
			}
		}
		else{
			if(webpages.contains(j)) {
				return true;
			}
			else {
				return false;
			}
		}
	}
	
	public ArrayList<Double> getProbability(int anNr, int fieldNr, String objectType) {
		ArrayList<Double> probabilityList = new ArrayList<Double>();
		Double sum = summationSim(anNr,fieldNr,objectType);
		for(int i = 1; i < Integer.parseInt(original.get(original.size()-1).get(0))+1;i++) {
			if(objectType.equals("host")) {	
				if(!getMappedOriginalHost().contains(i)) {
					Double value = (sum != 0?(calcSimilarity(anNr, i, fieldNr, objectType)/sum):0.0);
					probabilityList.add(value);	
				}
				else {
					probabilityList.add(0.0);
				}
			}
			else {
				if(!getMappedOriginalWebpage().contains(i)) {
					Double value = (sum != 0?(calcSimilarity(anNr, i, fieldNr, objectType)/sum):0.0);
					probabilityList.add(value);	
				}
				else {
					probabilityList.add(0.0);
				}
			}
		}
		return probabilityList;
	}
	
	public Double summationSim(int anNr, int fieldNr, String objectType) {
		Double res = 0.0;
		ArrayList<String> anon = getAnonList(anNr, fieldNr, objectType);
		for(int i = 1; i < Integer.parseInt(original.get(original.size()-1).get(0))+1;i++) {
			ArrayList<String> UK = new ArrayList<String>();
			for(List<String> og : original) {
				if((Integer.parseInt(og.get(0)) == i) && (og.get(1).equals(objectType))) {
					if(og.size()-1 >= fieldNr) {
						UK.add(og.get(fieldNr));
					}
					else {
						UK.add(".");
					}
				}
			}
			Entropy entropy2 = new Entropy(UK,anon);
			res += entropy2.L1similarity();
		}
		return res;
	}
	
	public ArrayList<String> getAnonList(int anNr, int fieldNr, String objectType) {
		ArrayList<String> anon = new ArrayList<String>();		
		for(List<String> anonPkt : anonymized) {
			if(Integer.parseInt(anonPkt.get(0)) == anNr && anonPkt.get(1).equals(objectType)) {
				anon.add(anonPkt.get(fieldNr));
			}
		}
		return anon;
	}
	
	public ArrayList<String> getUnanonList(int ogNr, int fieldNr, String objectType){
		ArrayList<String> UJ = new ArrayList<String>();
		for(List<String> unanonPkt : original) {
			if(Integer.parseInt(unanonPkt.get(0)) == ogNr && unanonPkt.get(1).equals(objectType)) {
				if(unanonPkt.size() > fieldNr) {
					UJ.add((unanonPkt.get(fieldNr)));
				}
				else {
					UJ.add(".");
				}
			}
		}
		return UJ;
	}
	
	public Double calcSimilarity(int anNr, int ogNr, int fieldNr, String objectType) {
		entropyCalc = new Entropy(getUnanonList(ogNr, fieldNr, objectType),getAnonList(anNr, fieldNr, objectType));
		Double anonUJ = entropyCalc.L1similarity();
		return anonUJ;
	}
		
	//Method for calculating the entropy for each field of an anonymized object.
	public ArrayList<String> fieldEntropy(int anonymizedObject, String objectType, int objectSizeA) {
		entropyCalc = new Entropy();
		ArrayList<String> entropyResults = new ArrayList<String>();
		for(int i = 2; i < objectSizeA; i++) {
			fieldEntropy = new HashMap<String, Double>();
			Double sum = summationSim(anonymizedObject, i, objectType);
			if(sum == 0.0) {
				entropyResults.add("");
			}
			else {
				for(int j = 1; j < Integer.parseInt(original.get(original.size()-1).get(0))+1;j++) {
					if(objectType.equals("host")) {
						if(!getMappedOriginalHost().contains(j)) {
							Double value = calcSimilarity(anonymizedObject, j, i, objectType)/sum;
							fieldEntropy.put(objectType + " AO " + anonymizedObject + " UO " + j + " FieldNr "+ i,
									value);
							//System.out.println("AO " + anonymizedObject + " FieldNr " + i + " UO " + j + "=" + value);			
						}
					}
					else {
						if(!getMappedOriginalWebpage().contains(j)) {
							Double value = calcSimilarity(anonymizedObject, j, i, objectType)/sum;
							fieldEntropy.put(objectType + " AO " + anonymizedObject + " UO " + j + " FieldNr "+ i,
									value);
							//System.out.println("AO " + anonymizedObject + " FieldNr " + i + " UO " + j + "=" + value);			
						}
					}
				}
				entropyResults.add(Double.toString(entropyCalc.entropy(fieldEntropy)));
			}
		}
		return entropyResults;
	}
	
	//Method to calculate the total entropy for all the fields of an object.
	public Double objectEntropy(int anonymizedObject, String objectType, int objectSizeA) {
		ArrayList<String> fieldEntropy = new ArrayList<String>(fieldEntropy(anonymizedObject, objectType,objectSizeA));
		Double addition = 0.0;
		for(String x : fieldEntropy) {
			try {
				addition += Double.parseDouble(x);
			}
			catch(NumberFormatException e) {
			}
		}
		return addition;
	}
	
	//Method that runs fieldEntropy() and objectEntropy() for all anonymized objects.	
	public HashMap<String, Double> forAllAnonymizedObjects(String objectType) {
		HashMap<String,Double> resultater = new HashMap<String, Double>();
		for(int i = 1; i < Integer.parseInt(anonymized.get(anonymized.size()-1).get(0))+1;i++) {
			if(objectType.equals("host")) {
				if(doesItContain(i, objectType) && !mappedAnonymizedHost.contains(i)) {
					resultater.put(""+i, objectEntropy(i,objectType,objectSizeA.get(Integer.toString(i))));		
				}
			}
			else {
				if(doesItContain(i, objectType) && !mappedAnonymizedWebpage.contains(i)) {
					resultater.put(""+i, objectEntropy(i,objectType,objectSizeA.get(Integer.toString(i))));		
				}
			}
		}
		return resultater;
	}	
	
	public ArrayList<String> getFieldEntropy(int anonymizedObject, String objectType, int objectSizeA) {
		return fieldEntropy(anonymizedObject, objectType, objectSizeA);
	}
	
	public HashMap<String,Integer> getSizes(int anonymizedObject) {
		HashMap<String, Integer> objectSizes = new HashMap<String, Integer>();
		objectSizes.put("anonymized",objectSizeA.get(Integer.toString(anonymizedObject)));
		return objectSizes;
	}
	
	public Double getMaxAverages(String objectType) {
		Double res = 0.0;
		Entropy e = new Entropy();
		for(String x : objectSizeA.keySet()) {
			if(objectType.equals("host")) {
				if(!mappedAnonymizedHost.contains(Integer.parseInt(x)) && hosts.contains(Integer.parseInt(x))) {
					res += objectSizeA.get(x)*e.log2((double) getNrOfObjectTypes(objectType));
				}
			}
			else {
				if(!mappedAnonymizedWebpage.contains(Integer.parseInt(x)) && webpages.contains(Integer.parseInt(x))) {
					res += objectSizeA.get(x)*e.log2((double) getNrOfObjectTypes(objectType));
				}
			}
		}
		return res;
	}
	
	public Double getMax(String objectType) {
		Entropy e = new Entropy();
		double max = Double.MIN_VALUE;
		for(String x : objectSizeA.keySet()) {
			if(objectType.equals("host")) {
				if(!mappedAnonymizedHost.contains(Integer.parseInt(x)) && hosts.contains(Integer.parseInt(x))) {
					int value = objectSizeA.get(x);
					if(value > max) {
						max = value;
					}
				}
			}
			else {
				if(!mappedAnonymizedHost.contains(Integer.parseInt(x)) && webpages.contains(Integer.parseInt(x))) {
					int value = objectSizeA.get(x);
					if(value > max) {
						max = value;
					}
				}
			}
		}
		if(objectType.equals("host")) {
			return max * e.log2((double) getNrOfObjectTypes(objectType) - mappedAnonymizedHost.size());
		}
		else {
			return max * e.log2((double) getNrOfObjectTypes(objectType) - mappedAnonymizedWebpage.size());
		}
	}
	
	
	public void toTextFile(String objectType) {
		final String FNAME = (objectType.equals("host")?
		"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\resultsForHost.dat":
			"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\resultsForWebpage.dat");
		
		try ( BufferedWriter bw = new BufferedWriter (new FileWriter (FNAME)) ) 
		{			
			for (String line : forAllAnonymizedObjects(objectType).keySet()) {
				//System.out.println(line);
				bw.write(line + " = " + forAllAnonymizedObjects(objectType).get(line) + "\n");
			}
			System.out.println("Created file " + FNAME);
			bw.close ();
			
		} catch (IOException e) {
			e.printStackTrace ();
		}
	}
	
		
	public static void main(String[] args) throws FileNotFoundException {
		ObjectAnonymity oa = new ObjectAnonymity(
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\FSO-IPv4.dat", 
				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\FSA-IPv4.dat");
		//System.out.println(oa.getProbability(3, 23, "host"));
		//System.out.println(oa.summationSim(3, 23, "host"));
		//oa.fieldEntropy(3, "host", 80);
		//oa.forAllAnonymizedObjects("host");
		System.out.println(oa.calcSimilarity(15, 6, 3, "host"));
		System.out.println("Her" + oa.forAllAnonymizedObjects("host"));

	}
}
