package Validering;

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

public class Entropy {
	
	private static HashMap<String, Double> px = new HashMap<String, Double>();
	private static HashMap<String, Double> py = new HashMap<String, Double>();
	ArrayList<String> merged = new ArrayList<String>();
	
	public Entropy() {
		
	}
	
	public Entropy(ArrayList<String> x, ArrayList<String> y){
		px = distribution1list(x);
		py = distribution1list(y);
		mergeLists(x, y);
	}
	
	//Method needed to merge the lists later used in distribution2lists().
	public void mergeLists(ArrayList<String> x, ArrayList<String> y) {
		for(int i = 0; i < Math.max(x.size(), y.size());i++) {
			try {
				merged.add(x.get(i)+"-"+y.get(i));
			}
			catch(IndexOutOfBoundsException e) {
				if(x.size() > y.size()) {
					merged.add(x.get(i));
				}
				else {
					merged.add(y.get(i));
				}
			}
		}
	}
	
	public ArrayList<String> getMerged(){
		return merged;
	}
	
	//Method used to find the distribution of a single list.
	public HashMap<String,Double> distribution1list(ArrayList<String> x) {
		HashMap<String,Double> distribution = new HashMap<String, Double>();
		for(String row : x) {
			int occurrences = Collections.frequency(x, row);
			distribution.put(row, (double) occurrences/x.size());
		}
		return distribution;
	}
	
	//Method used to find the joint distribution of two lists needed in mutual information.	
	public Double distribution2lists(String x, String y){
		int occurrences = Collections.frequency(merged, x+"-"+y);
	    return (double) occurrences/merged.size();
	}
	
	public Double entropy(HashMap<String,Double> px) {
		Double res = 0.0;
		for(String x : px.keySet()) {
			res += px.get(x)*log2(px.get(x));
		}
		return 0.0 - res;
	}
	
	public Double mutualInformation() {
		Double res = 0.0;
		for (String x : px.keySet() ) {
			for (String y : py.keySet()) {
				try {
					Double distribution = distribution2lists(x, y);
					Double probs = px.get(x)*py.get(y);
					res += (double) distribution*log2(distribution/probs);
				}
				catch(NumberFormatException e) {
					continue;
				}
			}
		}
		return res;	
	}
	
	public Double normalizedMutualInformation() {
		Double min = Math.min(entropy(px), entropy(py));
		return (min != 0.0? (double) mutualInformation()/min:0.0);	
	}
	
	public Double L1similarity() {
		Double res = 0.0;
		ArrayList<String> felles = new ArrayList<String>();
		if(!px.isEmpty() && !py.isEmpty()) {
			for (String x : px.keySet() ) {
				if(py.containsKey(x)) {
					//System.out.println("x finnes i y: " + x);
					felles.add(x);
					res += Math.abs(px.get(x) - py.get(x));
				}
				else {
					//System.out.println("x finnes ikke i y: " + x);
					res += Math.abs(px.get(x));
				}
			}
			for (String y : py.keySet() ) {
				if(!felles.contains(y)) {
					//System.out.println("y finnes ikke i x: " + y);
					res += Math.abs(py.get(y));
				}
			}
			if(felles.isEmpty()) {
				return 0.0;
			}
			else {
				Double truncatedDouble = BigDecimal.valueOf(res).setScale(14, RoundingMode.HALF_UP).doubleValue();
				Double result = 2.0 - truncatedDouble;
				return (result < 0.0?0.0:result);
			}
		}
		else {
			return 0.0;
		}
	}
	
	public Double log2(Double a) throws NumberFormatException{
		double d = a.doubleValue();
		if(d != 0) {
			Double res = Math.log(d) / Math.log(2);
			return res;
		}
		else {
			return 0.0;
		}
	}
	
	public HashMap<String, Double> getPX(){
		return px;
	}
	
	public HashMap<String, Double> getPY(){
		return py;
	}
	
	@Override
	public String toString() {
		return String.format("p(x): " + px + "\n" +
							"p(y): " + py + "\n" +
							"Entropy for p(x): " + "%.20f" + "\n" +
							"Entropy for p(y): " + "%.20f" + "\n" +
							"Mutual information: " + "%.20f" + "\n" +
							"Normalized mutual information: " + "%.20f" + "\n" +
							"L1similarity: " + "%.2f",
							entropy(px),entropy(py),mutualInformation(),
							normalizedMutualInformation(),L1similarity());
	}
	
	public static void main(String[] args) throws FileNotFoundException {
		ArrayList<String> fem = new ArrayList<String>();
		ArrayList<String> seks = new ArrayList<String>();
		ArrayList<List<String>> samlet = new ArrayList<>();
		Scanner s = new Scanner(new File("C:\\Users\\Petter\\Documents\\Master\\Datasets\\IPv4\\IIRoriginalIPv4.dat"));
		while(s.hasNextLine()) {	
			samlet.add(new ArrayList<String>(Arrays.asList(s.nextLine().split("\t"))));
		}
		
		for(List<String> line : samlet) {
			fem.add(line.get(8));
			seks.add(line.get(74));
		}
		s.close();
		
		ArrayList<String> forste = new ArrayList<String>(Arrays.asList("a", "a", "a", "a", "b", "b", "b", "b", "b"));
		ArrayList<String> andre = new ArrayList<String>(Arrays.asList("1", "1", "2", "2", "1", "1", "1", "1", "2"));
		
		ArrayList<String> ao91 = new ArrayList<String>(Arrays.asList(
				"1326581929000132658195700028.71364.4.15.203.A....3200000.0.0.0true041.42.111.83105.46.96.15264.4.15.2030.0.0.03200",
				"132658194700013265819470000.00064.4.15.193.AP...380180001000028.7130.0.0.10false6041.42.111.89105.46.96.14664.4.15.1930.0.0.1026060"));
		ArrayList<String> uo886 = new ArrayList<String>(Arrays.asList("1326581930000"));
		
		Entropy e = new Entropy(ao91,uo886);
//		System.out.println(e.entropy(px));
//		System.out.println(e.entropy(py));
	}

}
