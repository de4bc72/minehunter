package detect;

import javafx.util.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;

public class FlowRes {
    public String sip;
    public String dip;
    public double mean_error = 0;
    public double entropy = 0;

    public HashMap<Integer, LinkedList<EvaluationPair>> res_mp = new HashMap<>();
}
