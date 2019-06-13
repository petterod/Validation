package Validering;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;

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
	
	//Calculates the entropy of input px.
	public Double entropy(HashMap<String,Double> px) {
		Double res = 0.0;
		for(String x : px.keySet()) {
			res += px.get(x)*log2(px.get(x));
		}
		return 0.0 - res;
	}
	
	//Calculates the mutual information of px and py. Used in normalizedMutualInformation().
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
	
	//Calculates the normalized mutual information of px and py.
	public Double normalizedMutualInformation() {
		Double min = Math.min(entropy(px), entropy(py));
		return (min != 0.0? (double) mutualInformation()/min:0.0);	
	}
	
	//Calculates the L1 similarity of px and py.
	public Double L1similarity() {
		Double res = 0.0;
		ArrayList<String> common = new ArrayList<String>();
		if(!px.isEmpty() && !py.isEmpty()) {
			for (String x : px.keySet() ) {
				if(py.containsKey(x)) {
					common.add(x);
					res += Math.abs(px.get(x) - py.get(x));
				}
				else {
					res += Math.abs(px.get(x));
				}
			}
			for (String y : py.keySet() ) {
				if(!common.contains(y)) {
					res += Math.abs(py.get(y));
				}
			}
			if(common.isEmpty()) {
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
	
	//Calculates the 2 logarithm of input a.
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
}
