package detect;

import javafx.util.Pair;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import javax.xml.crypto.dom.DOMCryptoContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.*;

public class DetectOnline {
    public static int blockSeriesCurPos = 0;
    public static int shift_time = 1;

    public static void detectOnline(String pcapFilePath, HashMap<String, FlowRes> alerts) throws IOException{
        File input = new File(pcapFilePath);
        if(input.isFile()){
            detectOnlineFile(input, alerts);
        }
        else{
            detectOnlineDir(input, alerts);
        }
    }

    public static void detectOnlineDir(File pcapDir, HashMap<String, FlowRes> alerts) throws IOException{
        if(pcapDir.listFiles()!=null){
            for(File file :pcapDir.listFiles()){
                if(!file.isHidden()){
                    if(file.getName().contains("pcap")) {
                        blockSeriesCurPos = 0;
                        detectOnlineFile(file, alerts);
                    }
                }
            }
        }
    }

    public static int getBlockSeriesPos(long timestamp){
        int begin = 0;
        int end = Main.blockSeries.size();
        while(true){
            if(begin == end || (begin+1) == end){
                return begin;
            }
            int mid = (begin + end)/2;
            if(timestamp == Main.blockSeries.get(mid)){
                return mid;
            }
            if(timestamp < Main.blockSeries.get(mid)){
                end = mid;
            }else{
                begin = mid;
            }
        }
    }


    public static void detectOnlineFile(File pcapFile, HashMap<String, FlowRes> alerts) throws IOException{
        blockSeriesCurPos = 0;
        System.out.println(pcapFile.getCanonicalPath());
        System.out.println("===========");
        PacketHeader packet_header = new PacketHeader();
        FileInputStream fis = null;
        int packet_cnt = 0;
        try{
            fis = new FileInputStream(pcapFile);
            byte[] pcap_header = new byte[24];
            fis.read(pcap_header);
            //System.out.println(bytesToHexFun1(pcap_header));
            int len = 0;
            boolean isheader = true;
            byte[] buf = new byte[16];

            while ((len = fis.read(buf)) != -1) {
                if(isheader == true){
                    packet_header.set_header(buf);
                    int caplen = Helper.bytesToInt(packet_header.caplen,0,true);
                    buf = new byte[caplen];
                    isheader = false;
                }else{
                    int frame_len = Helper.bytesToInt(packet_header.len,0,true);
                    int timestamp = Helper.bytesToInt(packet_header.second,0,true);

                    if(blockSeriesCurPos == 0){
                        blockSeriesCurPos = getBlockSeriesPos(timestamp);
                        //System.out.println(timestamp + " " + blockSeriesCurPos);
                    }
                    byte[] ether_header = new byte[14];
                    byte[] ip_header = new byte[20];
                    System.arraycopy(buf,0,ether_header,0,14);
                    if(ether_header[12]==0x08&&ether_header[13]==0x00){
                        System.arraycopy(buf,14,ip_header,0,20);
                        byte[] src_ip_byte = new byte[4];
                        byte[] dst_ip_byte = new byte[4];
                        System.arraycopy(ip_header,12,src_ip_byte,0,4);
                        System.arraycopy(ip_header,16,dst_ip_byte,0,4);
                        String sip = Helper.bytesToIp(src_ip_byte);
                        String dip = Helper.bytesToIp(dst_ip_byte);
                        int protocol = ip_header[9];
                        String id = sip;
                        String sipdip = sip + "_" + dip;
                        if(protocol==6){
                            /*interval alert*/
                            if(timestamp > Main.blockSeries.get(blockSeriesCurPos + 1)){
                                //System.out.println("Interval alert: " + Main.blockSeries.get(blockSeriesCurPos + 1));

                                intervalAlertSingle(alerts);

                                blockSeriesCurPos += 1;
                            }


                            /*process packet*/
                            processPacket(sip, dip, timestamp + shift_time, frame_len);
                            //System.out.println(timestamp);
                        }
                    }

                    isheader = true;
                    buf = new byte[16];
                }
            }
        }catch(IOException e){
            e.printStackTrace();
        }
    }

    public static void processPacket(String sip, String dip, long timestamp, int frame_len){
        String sipdip = sip + "_" + dip;
        Main.allFlow.all_sipdip_set.add(sipdip);

        if(frame_len > Main.MIN_PACKET_LENGTH) {
            //System.out.println(timestamp);
            Main.allFlow.active_flow_set.add(sipdip);

            Flow flow = Main.allFlow.all_flow_map.get(sipdip);
            if (flow == null) {
                Flow f = new Flow(sip, dip, timestamp);
                Main.allFlow.all_flow_map.put(sipdip, f);
            } else {
                flow.addOnline(timestamp);
            }
        }
    }


    public static void intervalAlertSingle(HashMap<String, FlowRes> alerts){
        int matchStartPos = blockSeriesCurPos - Main.K;
        HashSet<String> delete_flows = new HashSet<>();

        for (String sipdip : Main.allFlow.active_flow_set) {
            Flow flow = Main.allFlow.all_flow_map.get(sipdip);
            if(flow == null){
                continue;
            }

            ArrayList<Long> errors = new ArrayList<>();

            for (MatchPairData m : flow.matchPair) {
                if (m.matchPos >= matchStartPos) {
                    errors.add(m.matchTimestamp - m.blockTimestamp);
                }
            }

            //delete useless history
            if(errors.size() == 0){
                delete_flows.add(sipdip);
            }
            else {
                ArrayList<Long> errors_remove = DetectCore.abnormal_value_remove(errors);

                if (errors_remove.size() >= Main.nodeNumMin) {
                    long sum = 0;
                    for (long l : errors_remove) {
                        sum += l;
                    }
                    double error = (double) sum / errors_remove.size();
                    double entropy = computeEntropy(flow.times);

                    if (error < Main.meanError && entropy > Main.entropyThreshold) {
                        //System.out.println("Alert: " + error + " " + sipdip);
                        FlowRes flowRes = new FlowRes();
                        flowRes.sip = flow.sip;
                        flowRes.dip = flow.dip;
                        flowRes.mean_error = error;
                        flowRes.entropy = entropy;
                        alerts.put(sipdip, flowRes);
                    }
                }
            }
        }

        for(String sipdip: delete_flows){
            Flow flow = Main.allFlow.all_flow_map.get(sipdip);

            flow.times.clear();
            flow.matchPair.clear();
            Main.allFlow.active_flow_set.remove(sipdip);
        }
    }


    public static double computeEntropy(LinkedList<Long> times){
        int dim = times.size() - 1;
        HashMap<Long,Integer> interval_counter = new HashMap<Long,Integer>();

        long last_time = 0;
        for(Long time:times){
            if(last_time != 0){
                long tmp = time - last_time;
                if(interval_counter.containsKey(tmp)){
                    int value_tmp = interval_counter.get(tmp);
                    value_tmp++;
                    interval_counter.put(tmp, value_tmp);
                }else{
                    interval_counter.put(tmp, 1);
                }
            }
            last_time = time;
        }

        double[] s = new double[interval_counter.size()];
        int tmp_index = 0;
        for(Map.Entry map_element : interval_counter.entrySet()){
            int tmp_value = (int)map_element.getValue();
            s[tmp_index] =( (double)tmp_value ) / (times.size()-1);
            tmp_index++;
        }

        double r=0; int i;
        for(i=0;i<interval_counter.size();i++)
            if (s[i]!=0) r+=s[i]*Math.log(s[i]);
        r=-r/((double) Math.log(2));
        return r;
    }
}
