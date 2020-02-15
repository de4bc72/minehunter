package detect;

import javafx.util.Pair;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;

public class Flow implements Serializable {
    public String sip;
    public String dip;
    public ArrayList<Long> input = new ArrayList<>();
    public ArrayList<Long> shift_input = new ArrayList<>();
    public LinkedList<MatchPairData> matchPair = new LinkedList<>();
    public int matchPos = 0;

    public LinkedList<Long> times = new LinkedList<>();

    public Flow(String sip, String dip){
        this.sip = sip;
        this.dip = dip;
    }

    public Flow(String sip, String dip, long timestamp){
        this.sip = sip;
        this.dip = dip;
        //this.input.add(timestamp);
        this.times.add(timestamp);

        matchPos = DetectOnline.getBlockSeriesPos(timestamp);
    }


    public void add (long time){
        if(input.size() == 0){
            input.add(time);
            shift_input.add(time);
        }
        else{
            if(time > input.get(input.size() - 1)){
                input.add(time);
                shift_input.add(time);
            }
            else {
                boolean found = false;
                for (int i = input.size() - 2; i >= 0; i--) {
                    if (time > input.get(i) && time < input.get(i + 1)) {
                        input.add(i + 1, time);
                        shift_input.add(i + 1, time);
                        found = true;
                        break;
                    }
                }
                if (!found && time < input.get(0)) {
                    input.add(0, time);
                    shift_input.add(0, time);
                }
            }
        }
    }

    public void addOnline(long timestamp){
        this.times.add(timestamp);

        if(timestamp >= Main.blockSeries.get(matchPos + 1)){
            matchPos += 1;
            while(timestamp >= Main.blockSeries.get(matchPos + 1)){
                matchPos += 1;
            }
            matchPair.add(new MatchPairData(matchPos, Main.blockSeries.get(matchPos), timestamp));
        }
    }


    public void shift(int value){
        for(int i=0;i<input.size();i++){
            shift_input.set(i, input.get(i)+value);
        }
    }



}