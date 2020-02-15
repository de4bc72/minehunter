package detect;

import java.io.*;
import java.text.ParseException;
import java.util.*;

public class Main {
    public static int MIN_PACKET_LENGTH = 250;

    public static AllFlow allFlow = new AllFlow();
    public static ArrayList<Long> blockSeries = new ArrayList<>();

    public static int K = 20;
    public static int nodeNumMin = 9;
    public static double meanError = 5.0;
    public static double entropyThreshold = 2.5;

    public static void main(String[] args) throws Exception{
        String blockFilePath = "", pcapFilePath = "";
        try {
            Properties prop = new Properties();
            InputStream in = new BufferedInputStream(new FileInputStream("/Users/rick/IdeaProjects/minehunter/config.properties"));
            prop.load(in);
            blockFilePath = prop.getProperty("blockFilePath");
            pcapFilePath = prop.getProperty("pcapFilePath");
        }
        catch (Exception e){
            System.out.println("config.properties error");
            e.printStackTrace();
        }

        //Number of Valid Sub-Intervals
        int nodeNumMin = 9;

        //Sequence Distance
        double meanError = 5.0;

        //Entropy Threshold
        double entropyThreshold = 2.5;

        detectOnlineSingle(pcapFilePath, blockFilePath, nodeNumMin, meanError, entropyThreshold);
    }

    public static void detectOnlineSingle(String pcapFilePath, String blockFilePath, int nodeNumMin, double meanError, double entropyThreshold) throws IOException, ParseException{
        Main.blockSeries.clear();
        readBlockSeries(blockFilePath);

        Main.allFlow.all_flow_map.clear();
        Main.allFlow.all_sipdip_set.clear();
        Main.allFlow.active_flow_set.clear();

        HashMap<String, FlowRes> alerts = new HashMap<>();
        DetectOnline.detectOnline(pcapFilePath, alerts);

        System.out.println("====Results====");
        System.out.printf("%-35s %s\t%s\n", "sip_dip", "Sequence Distance", "Entropy");
        for(Map.Entry<String, FlowRes> e: alerts.entrySet()){
            FlowRes flowRes = e.getValue();
            System.out.printf("%-35s %17f\t%f\n", flowRes.sip + "_" + flowRes.dip, flowRes.mean_error, flowRes.entropy);
        }
        System.out.println("All Flows count = " + Main.allFlow.all_sipdip_set.size());
        System.out.println("Alert count = " + alerts.size());
    }

    public static void readBlockSeries(String blockFilePath) throws IOException, ParseException{
        String tempString;
        BufferedReader reader_pattern  = new BufferedReader(new FileReader(blockFilePath));

        while ((tempString = reader_pattern.readLine()) != null){
            Main.blockSeries.add(Long.valueOf(tempString.split(",")[0]));
        }
        reader_pattern.close();
    }
}
