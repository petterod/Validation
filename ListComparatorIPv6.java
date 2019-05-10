package Validering;

import java.util.Comparator;
import java.util.List;

class ListComparatorIPv6 implements Comparator<List<String>>{

    public int compare(List<String> string1, List<String> string2) {
        String a = string1.get(28);
        String b = string2.get(28);
        return Integer.parseInt(a)-Integer.parseInt(b);
    }
}
