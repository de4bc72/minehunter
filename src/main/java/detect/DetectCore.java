package detect;

import javafx.util.Pair;

import java.io.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class DetectCore{
    public static int SHIFT_STEP = 1;
    private static int NODE_NUM_MIN = 10;
    private static int PATTERN_MAX_LENGTH = 100000;
    private static double error_infinite = 100;
    public static int current_length = 0;
    public static long[] pattern = new long[PATTERN_MAX_LENGTH];


    public static long[] abnormal_value_remove2(HashMap<Long, Long> mp_interval_error,int len){
        long[] tmp = new long[len];
        Pair<Long, Long>[] interval_error = new Pair[len];
        int t = 0;
        for(Map.Entry<Long, Long> e: mp_interval_error.entrySet()){
            interval_error[t] = new Pair<>(e.getKey(), e.getValue());
            tmp[t] = e.getKey();
            t++;
        }

        if(len>4){
            Arrays.sort(interval_error, new Comparator<Pair<Long, Long>>() {
                @Override
                public int compare(Pair<Long, Long> o1, Pair<Long, Long> o2) {
                    if(o1.getValue().longValue() == o2.getValue().longValue()) return 0;
                    return o1.getValue() > o2.getValue() ? 1 : -1;
                }
            });

            int q1_index = len/4 - 1;

            int q3_index = len*3/4 - 1;
            long iqr = interval_error[q3_index].getValue() - interval_error[q1_index].getValue();
            double lower_bound = ((double)interval_error[q1_index].getValue())-1.5*(double)iqr;
            double upper_bound = ((double)interval_error[q3_index].getValue())+1.5*(double)iqr;
            ArrayList<Long> res_tmp = new ArrayList<Long>();
            for(int i=0;i<len;i++){
                if(interval_error[i].getValue() >= lower_bound && interval_error[i].getValue() <= upper_bound){
                    res_tmp.add(interval_error[i].getKey());
                }
            }
            long[] res = new long[res_tmp.size()];
            for(int i=0;i<res_tmp.size();i++){
                res[i] = res_tmp.get(i);
            }
            return res;
        }
        return tmp;
    }

    public static ArrayList<Long> abnormal_value_remove(ArrayList<Long> errors){
        int len = errors.size();
        ArrayList<Long> tmp = new ArrayList<>(len);
        for(long l:errors){
            tmp.add(l);
        }

        if(len>4){
            Collections.sort(tmp);
            int q1_index = len/4 - 1;
            int q3_index = len*3/4 - 1;
            long iqr = tmp.get(q3_index) - tmp.get(q1_index);
            double lower_bound = ((double)tmp.get(q1_index))-1.5*(double)iqr;
            double upper_bound = ((double)tmp.get(q3_index))+1.5*(double)iqr;
            ArrayList<Long> res_tmp = new ArrayList<Long>();
            for(int i=0;i<len;i++){
                if(tmp.get(i) >= lower_bound && tmp.get(i) <= upper_bound){
                    res_tmp.add(tmp.get(i));
                }
            }
            return res_tmp;
        }
        return tmp;
    }


    public static float Entropy(ArrayList<Long> input){
        int dim = input.size() - 1;
        HashMap<Long,Integer> interval_counter = new HashMap<Long,Integer>();
        for (int i=0;i<dim;i++){
            long tmp = input.get(i+1) - input.get(i);
            if(interval_counter.containsKey(tmp)){
                int value_tmp = interval_counter.get(tmp);
                value_tmp++;
                interval_counter.put(tmp, value_tmp);
            }else{
                interval_counter.put(tmp, 1);
            }
        }
        float[] s = new float[interval_counter.size()];
        int tmp_index = 0;
        for(Map.Entry map_element : interval_counter.entrySet()){
            int tmp_value = (int)map_element.getValue();
            s[tmp_index] =( (float)tmp_value ) / (input.size()-1);
            tmp_index++;
        }

        float r=0; int i;
        for(i=0;i<interval_counter.size();i++)
            if (s[i]!=0) r+=s[i]*Math.log(s[i]);
        r=-r/((float) Math.log(2));
        return r;
    }


    public static int location(long input){
        int begin = 0;
        int end = current_length;
        while(true){
            if(begin == end || (begin+1) == end){
                return begin;
            }
            int tmp = (begin + end)/2;
            if(input == pattern[tmp]){
                return tmp;
            }
            if(input < pattern[tmp]){
                end = tmp;
            }else{
                begin = tmp;
            }
        }
    }


    public static void generate_interval_arr(ArrayList<Long> input, ArrayList<Long> vec1, ArrayList<Long> vec2){
        int length = input.size();
        if(length == 0){
            return;
        }


        HashMap<Long, Long> mp_interval_error = new HashMap<>();
        HashMap<Long, Pair<Long, Long>> mp_interval_pair = new HashMap<>();

        for(int i = 0;i < length;i++) {
            int pos = location(input.get(i));
            long d1 = Math.abs(input.get(i) - pattern[pos]);
            long d2 = Math.abs(pattern[pos + 1] - input.get(i));
            long d = 0;
            Pair<Long, Long> pair = null;


            if(d1 < d2){
                d = d1;
                pair = new Pair<>(pattern[pos], input.get(i));

            }
            else{
                d = d2;
                pair = new Pair<>(pattern[pos + 1], input.get(i));
            }



            if(mp_interval_error.containsKey(pattern[pos])){
                if(d < mp_interval_error.get(pattern[pos])){
                    mp_interval_error.put(pattern[pos], d);
                    mp_interval_pair.put(pattern[pos], pair);
                }
            }
            else{
                mp_interval_error.put(pattern[pos], d);
                mp_interval_pair.put(pattern[pos], pair);
            }

        }

        long[] normal_intervals = abnormal_value_remove2(mp_interval_error, mp_interval_error.size());
        for(int i = 0;i < normal_intervals.length;i++){
            vec1.add(mp_interval_pair.get(normal_intervals[i]).getKey());
            vec2.add(mp_interval_pair.get(normal_intervals[i]).getValue());
        }

        Collections.sort(vec1);
        Collections.sort(vec2);


        /*
        HashMap<Long, Long> dismp = new HashMap<>();
        HashMap<Long, Long> pairmp = new HashMap<>();
        for(int i = 0;i < length;i++){
            int pos = location(input.get(i));
            long d1 = Math.abs(input.get(i) - pattern[pos]);
            long d2 = Math.abs(pattern[pos + 1] - input.get(i));

            if(d1 < d2){
                if(dismp.containsKey(pattern[pos])){
                    long mindis1 = dismp.get(pattern[pos]);
                    if(d1 < mindis1){
                        dismp.put(pattern[pos], d1);
                        pairmp.put(pattern[pos], input.get(i));
                    }
                }
                else{
                    dismp.put(pattern[pos], d1);
                    pairmp.put(pattern[pos], input.get(i));
                }
            }
            else{
                if(dismp.containsKey(pattern[pos + 1])){
                    long mindis2 = dismp.get(pattern[pos + 1]);
                    if(d2 < mindis2){
                        dismp.put(pattern[pos + 1], d2);
                        pairmp.put(pattern[pos + 1], input.get(i));
                    }
                }
                else{
                    dismp.put(pattern[pos + 1], d2);
                    pairmp.put(pattern[pos + 1], input.get(i));
                }
            }
        }

        long[] normal_intervals = abnormal_value_remove2(dismp, dismp.size());
        Arrays.sort(normal_intervals);
        for(long l:normal_intervals){
            vec1.add(l);
            vec2.add(pairmp.get(l));
        }
        */
    }


    public static void get_interval_errors(ArrayList<Long> input, ArrayList<Long> errors){
        ArrayList<Long> vec1 = new ArrayList<>();
        ArrayList<Long> vec2 = new ArrayList<>();
        generate_interval_arr(input, vec1, vec2);

        for(int i = 0;i < vec2.size();i++){
            errors.add(vec2.get(i) - vec1.get(i));
        }
    }


    public static double timeseries_error(ArrayList<Long> input, int node_num_min){
        ArrayList<Long> vec1 = new ArrayList<>();
        ArrayList<Long> vec2 = new ArrayList<>();
        generate_interval_arr(input, vec1, vec2);

        //System.out.println(vec1);
        //System.out.println(vec2);
        ArrayList<Long> errors = new ArrayList<>();
        for(int i = 0;i < vec2.size();i++){
            errors.add(vec2.get(i) - vec1.get(i));
        }
        //System.out.println(errors);

        if(vec1.size() <= node_num_min){
            return error_infinite;
        }
        else{
            long t = 0;
            for(int i = 0;i < vec1.size();i++){
                t += Math.abs(vec1.get(i) - vec2.get(i));
            }
            return (double)t / vec1.size();
        }
    }


    public static void detect(AllFlow allFlow, String blockFilePath, int nodeNumMin,
                              double meanError, double entropyThreshold, int maxShiftNum,
                              ArrayList<FlowRes> alertFlows) throws IOException, ParseException{
        String blockInputPath = blockFilePath;
        /*initialize pattern*/
        current_length = 0;
        pattern = new long[PATTERN_MAX_LENGTH];

        String tempString;
        BufferedReader reader_pattern  = new BufferedReader(new FileReader(blockInputPath));

        while ((tempString = reader_pattern.readLine()) != null){
            pattern[current_length] = Long.parseLong(tempString.split(",")[0]);
            current_length++;
        }

        Arrays.sort(pattern,0,current_length);
        reader_pattern.close();

        if(allFlow.all_flow_map.size() == 0){
            System.out.println("all_flow_map size = 0");
            return;
        }
        for(Map.Entry<String, Flow> entry: allFlow.all_flow_map.entrySet()){
            if(entry.getValue().input.size()!=0){
                int shift_num=0;
                String sipdip = entry.getValue().sip + "_" + entry.getValue().dip;

                //error
                double error = timeseries_error(entry.getValue().input, nodeNumMin);
                for(int i=1 ;i <= maxShiftNum;i=i+SHIFT_STEP){
                    entry.getValue().shift(-i);
                    double tmp = timeseries_error(entry.getValue().shift_input, nodeNumMin);
                    if(tmp < error ){
                        error = tmp;
                        shift_num = -i;
                    }
                }

                entry.getValue().shift(1);
                double tmp = timeseries_error(entry.getValue().shift_input, nodeNumMin);
                if(tmp < error ){
                    error = tmp;
                    shift_num = 1;
                }

                entry.getValue().shift(shift_num);
                double entropy = Entropy(entry.getValue().shift_input);

                if(error < meanError && entropy > entropyThreshold){
                    FlowRes flowRes = new FlowRes();
                    flowRes.sip = entry.getValue().sip;
                    flowRes.dip = entry.getValue().dip;
                    flowRes.mean_error = error;
                    flowRes.entropy = entropy;
                    alertFlows.add(flowRes);
                }
                System.out.println(sipdip + "," + error + "," + entropy + "," + shift_num);
            }
        }
    }
}