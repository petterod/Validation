package Validering;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;

public class ResultsCalculationFinal{
	
	//Finner AO med den laveste verdien fra ObjectAnonymity
	//For AO: finner feltet med lavest entropy
	//For felt: finner object med høyest sannsynlighet
	
	ObjectAnonymity3 oa;
	HashMap<String, Double> hostResults;
	HashMap<String, Double> webpageResults;
	Integer ao;
	Integer anonymizedObject;
	ArrayList<Double> hostAverages = new ArrayList<Double>();
	ArrayList<Double> webpageAverages = new ArrayList<Double>();
	ArrayList<Double> hostAveragesMax = new ArrayList<Double>();
	ArrayList<Double> webpageAveragesMax = new ArrayList<Double>();
	ArrayList<Integer> mismatchesHost = new ArrayList<Integer>();
	ArrayList<Integer> mismatchesWebpage = new ArrayList<Integer>();
	
	public ResultsCalculationFinal(String originals, String anonymized, String FNAME) throws FileNotFoundException {
		oa = new ObjectAnonymity3(originals,anonymized);
		iteration();
		toTextFile(FNAME);
	}
	
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
	
	public Integer getLowestEntropy(String objectType) {
		anonymizedObject = null;
	    String minKey = null;
	    double minValue = Double.MAX_VALUE;
	    //System.out.println(hostResults);
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
//	    System.out.println("Entropies for all anonymized objects:");
//	    System.out.println(hostResults);
//	    System.out.println("The lowest entropy belongs to anonymized object " + minKey + "\n");
	    anonymizedObject = Integer.parseInt(minKey);
	    return anonymizedObject;
	}
	
	public Integer getLowestField(int anonymizedObject, String objectType) {
		ao = oa.getSizes(anonymizedObject).get("anonymized");
		String minKey = null;
		double minValue = Double.MAX_VALUE;
		for(int i = 2; i < ao-2;i++) {
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
//		System.out.println("Entropies for all fields of the anonymized object:");
//		System.out.println(oa.getFieldEntropy(anonymizedObject,objectType,ao, uo));
//		System.out.println("The lowest entropy belongs to field " + minKey + "\n");
		return Integer.parseInt(minKey);
	}
	
	public Integer getHighestProbability(String objectType) {
		int lowestField = getLowestField(anonymizedObject,objectType);
		ArrayList<Double> probabilities = oa.getProbability(anonymizedObject,lowestField,objectType);
		if(probabilities.stream().mapToDouble(f -> f.doubleValue()).sum() == 0.0) {
			System.out.println("her " + oa.summationSim(anonymizedObject, lowestField, objectType));
			System.out.println("AnonymizedObject is " + anonymizedObject);
			System.out.println("Lowest field is " + lowestField);
//			System.out.println("probabilities " + probabilities);
//			System.out.println("burde vært " + oa.getCalcSimilarity(19, 23, "host"));
//			System.out.println(oa.getAllEntropyValues(anonymizedObject));
//			System.out.println(oa.getValues(19, 23));
//			for(int i = 1; i < 132; i++) {
//				System.out.println(oa.getValues2(i, 23));
//			}
		}
		Integer maxKey = null;
		double max = Double.MIN_VALUE;
		for(int i=0; i<probabilities.size(); i++){
			double value = probabilities.get(i).doubleValue();
			if(value > max){
				max = value;
				maxKey = i + 1;
		    }
		}
//		System.out.println("The probabilities of all unanonymized objects for this field and this anonymized object:");
//		System.out.println(probabilities);
//		System.out.println("The highest probability belongs to unanonymized object " + maxKey + "\n");
		return maxKey;
	}
	
	public void iteration() {
		int hostMismatches = 0;
		int webpageMismatches = 0;
		while (oa.getMappedAnonymizedHost().size() + oa.getMappedAnonymizedWebpage().size() < oa.getNrOfObjects()) {
			hostResults = oa.forAllAnonymizedObjects("host");
			if(!hostResults.isEmpty()) {
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
			else {
				webpageResults = oa.forAllAnonymizedObjects("webPage");
				if(!webpageResults.isEmpty()) {
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
			}
		}
		System.out.println(hostAverages);
		System.out.println(webpageAverages);
		System.out.println(hostAveragesMax);
		System.out.println(webpageAveragesMax);
		System.out.println(mismatchesHost);
		System.out.println(mismatchesWebpage);
	}
	
		//Metode for å finne auxiliary information fra entropy-målet (det uanonymiserte objektet som har høyest entropy
	//med det anonymiserte objektet legges til som en mapping mellom uanonymisert og anonymisert.
	public void findingAuxiliaryInformation() {
		
	}
	
	//Metode for å legge til auxiliary information til neste runde av entropy-kjøring.
	public void addingAuxiliaryInformation() {
		
	}
	
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
//		ResultsCalculationFinal rs = new ResultsCalculationFinal(
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\FSO-IPv4.dat", 
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\FSA-IPv4.dat",
//				"C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\Results3-IPv4.csv");
		if (args.length !=3) {
		      System.err.println("usage: java -jar jarfile.jar originalInput.dat anonymizedInput.dat results.csv \n");
		      System.exit(-1);
		    }
		else {
			ResultsCalculationFinal rs = new ResultsCalculationFinal(args[0],args[1],args[2]);
		}
	}
}
