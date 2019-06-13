package Validering;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;

public class Validation{
	
	ObjectAnonymity oa;
	HashMap<String, Double> hostResults;
	HashMap<String, Double> webpageResults;
	Integer features;
	Integer anonymizedObject;
	ArrayList<Double> hostAverages = new ArrayList<Double>();
	ArrayList<Double> webpageAverages = new ArrayList<Double>();
	ArrayList<Double> hostAveragesMax = new ArrayList<Double>();
	ArrayList<Double> webpageAveragesMax = new ArrayList<Double>();
	ArrayList<Integer> mismatchesHost = new ArrayList<Integer>();
	ArrayList<Integer> mismatchesWebpage = new ArrayList<Integer>();
	
	public Validation(String originals, String anonymized, String FNAME) throws FileNotFoundException {
		oa = new ObjectAnonymity(originals,anonymized);
		iteration();
		toTextFile(FNAME);
	}
	
	//Calculates the average entropy of either hostResults or webpageResults.
	public Double calculateAverageEntropy(String objectType) {
		Double res = 0.0;
		if(objectType.equals("host")) {
			for(String key : hostResults.keySet()) {
				res += hostResults.get(key);
			}
			Double result = (res != 0 || !hostResults.isEmpty()? res/hostResults.size():0.0);
			hostAverages.add(result);
			return result;
		}
		else {
			for(String key : webpageResults.keySet()) {
				res += webpageResults.get(key);
			}
			Double result = (res != 0 || !webpageResults.isEmpty()? res/webpageResults.size():0.0);
			webpageAverages.add(result);
			return result;
		}	
	}
	
	//Finds the anonymized object in either hostResults or webpageResults with the lowest entropy.
	public Integer getLowestEntropy(String objectType) {
		anonymizedObject = null;
	    String minKey = null;
	    double minValue = Double.MAX_VALUE;
	    if(objectType.equals("host")) {
		    for (String key : hostResults.keySet()) {
		        double value = hostResults.get(key).doubleValue();
		        if (value < minValue) {
		            minValue = value;
		            minKey = key;
		        }
		    }
	    }
	    else {
	    	for (String key : webpageResults.keySet()) {
			    double value = webpageResults.get(key).doubleValue();
			    if (value < minValue) {
			        minValue = value;
			        minKey = key;
			    }
	    	}
	    }
	    anonymizedObject = Integer.parseInt(minKey);
	    return anonymizedObject;
	}
	
	//Finds the feature for anonymizedObject with the lowest entropy.
	public Integer getLowestFeature(int anonymizedObject, String objectType) {
		features = oa.getSizes(anonymizedObject).get("anonymized");
		String minKey = null;
		double minValue = Double.MAX_VALUE;
		for(int i = 2; i < features-2;i++) {
			try {
				double value = Double.parseDouble(oa.getFieldEntropy(anonymizedObject,i-2));
				if (value < minValue) {
					minValue = value;
					minKey = "" + i;
				}
			}
			catch(NumberFormatException e) {
				continue;
			}
		}
		return Integer.parseInt(minKey);
	}
	
	//Finds the unanonymized object with the highest probability.
	public Integer getHighestProbability(String objectType) {
		int lowestFeature = getLowestFeature(anonymizedObject,objectType);
		ArrayList<Double> probabilities = oa.getProbability(anonymizedObject,lowestFeature,objectType);
		Integer maxKey = null;
		double max = Double.MIN_VALUE;
		for(int i=0; i<probabilities.size(); i++){
			double value = probabilities.get(i).doubleValue();
			if(value > max){
				max = value;
				maxKey = i + 1;
		    }
		}
		return maxKey;
	}
	
	//Performs the mapping while the size of mapped objects is smaller than the total number of objects.
	//For every iteration, finds the anonymized object with the lowest entropy, and the unanonymized object
	//with the highest probability of being equal to this anonymized object. Also keeps track of number of
	//mismappings. Does mapping for all host objects first, then all web page objects. 
	public void iteration() {
		int hostMismatches = 0;
		int webpageMismatches = 0;
		while (oa.getMappedAnonymizedHost().size() + oa.getMappedAnonymizedWebpage().size() < oa.getNrOfObjects()) {
			hostResults = oa.forAllAnonymizedObjects("host");
			if(hostResults.size() > 1) {
				System.out.println("Average anonymized object entropy for host: "  + calculateAverageEntropy("host"));
				hostAveragesMax.add(oa.getMax("host"));
				getLowestEntropy("host");
				int unanonymizedObject = getHighestProbability("host");
				if(anonymizedObject != unanonymizedObject) {
					hostMismatches ++;	
				}
				mismatchesHost.add(hostMismatches);
				System.out.println("AO " + anonymizedObject + " UO " + unanonymizedObject);
				oa.setMapped(anonymizedObject, unanonymizedObject,"host");
				System.out.println("-------------------------------------------------------------------------------");
			}
			else if(hostResults.size() == 1){
				System.out.println("Average anonymized object entropy for host: "  + calculateAverageEntropy("host"));
				hostAveragesMax.add(oa.getMax("host"));
				getLowestEntropy("host");
				int unanonymizedObject = 0;
				for(Integer host : oa.getHosts()) {
					if(!oa.getMappedAnonymizedHost().contains(host)) {
						unanonymizedObject = host;
						break;
					}
				}
				if(anonymizedObject != unanonymizedObject) {
					hostMismatches ++;	
				}
				mismatchesHost.add(hostMismatches);
				System.out.println("AO " + anonymizedObject + " UO " + unanonymizedObject);
				oa.setMapped(anonymizedObject, unanonymizedObject,"host");
				System.out.println("-------------------------------------------------------------------------------");
			}
			else {
				webpageResults = oa.forAllAnonymizedObjects("webPage");
				if(webpageResults.size() > 1) {
					System.out.println("Average anonymized object entropy for web pages: "  + calculateAverageEntropy("webPage"));
					webpageAveragesMax.add(oa.getMax("webPage"));
					getLowestEntropy("webPage");
					int unanonymizedObject = getHighestProbability("webPage");
					if(anonymizedObject != unanonymizedObject) {
						webpageMismatches ++;
					}
					mismatchesWebpage.add(webpageMismatches);
					System.out.println("AO " + anonymizedObject + " UO " + unanonymizedObject);		
					oa.setMapped(anonymizedObject, unanonymizedObject,"webPage");
					System.out.println("-------------------------------------------------------------------------------");
				}
				else if(webpageResults.size() == 1){
					System.out.println("size is 1");
					System.out.println("Average anonymized object entropy for host: "  + calculateAverageEntropy("webPage"));
					webpageAveragesMax.add(oa.getMax("webPage"));
					getLowestEntropy("webPage");
					int unanonymizedObject = 0;	
					for(Integer webpage : oa.getWebpages()) {
						if(!oa.getMappedAnonymizedWebpage().contains(webpage)) {
							unanonymizedObject = webpage;
							break;
						}
					}
					if(anonymizedObject != unanonymizedObject) {
						webpageMismatches ++;	
					}
					mismatchesWebpage.add(webpageMismatches);
					System.out.println("AO " + anonymizedObject + " UO " + unanonymizedObject);
					oa.setMapped(anonymizedObject, unanonymizedObject,"webPage");
					System.out.println("-------------------------------------------------------------------------------");
				}
				else {
					System.out.println("Completed");
					break;
				}
			}
		}
		System.out.println(hostAverages);
		System.out.println(webpageAverages);
		System.out.println(hostAveragesMax);
		System.out.println(webpageAveragesMax);
		System.out.println(mismatchesHost);
		System.out.println(mismatchesWebpage);
	}
	
	//Method to write lines from the new log to csv file.
	public void toTextFile(String FNAME) {
	    try (PrintWriter writer = new PrintWriter(new File(FNAME))) {
	        StringBuilder sb = new StringBuilder();
	        for(int i = 0; i < hostAverages.size();i++) {
	        	sb.append(hostAverages.get(i));
	        	sb.append(',');
	        	sb.append(hostAveragesMax.get(i));
	        	sb.append(',');
	        	sb.append(mismatchesHost.get(i));
	        	sb.append('\n');
	        }
	        sb.append('\n');
	        for(int i = 0; i < webpageAverages.size();i++){
	        	sb.append(webpageAverages.get(i));
	        	sb.append(',');
	        	sb.append(webpageAveragesMax.get(i));
	        	sb.append(',');
	        	sb.append(mismatchesWebpage.get(i));
	        	sb.append('\n');
	        }
	        writer.write(sb.toString());
	        System.out.println("Created file " + FNAME);
	      } catch (FileNotFoundException e) {
	        System.out.println(e.getMessage());
	      }
	}	
	
	public static void main(String[] args) throws FileNotFoundException {
		if (args.length !=3) {
		      System.err.println("usage: java -jar jarfile.jar originalInput.dat anonymizedInput.dat results.csv \n");
		      System.exit(-1);
		    }
		else {
			Validation rs = new Validation(args[0],args[1],args[2]);
		}
	}
}
