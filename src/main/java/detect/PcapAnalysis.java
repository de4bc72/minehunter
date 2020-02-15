package detect;

import java.io.*;

public class PcapAnalysis {
    public static void analysis_file(File pcap_file) throws IOException{
        System.out.println(pcap_file.getName());
        PacketHeader packet_header = new PacketHeader();
        FileInputStream fis = null;
        try{
            fis = new FileInputStream(pcap_file);
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
                    int second = Helper.bytesToInt(packet_header.second,0,true);
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
                        if(protocol==6){
                            String sipdip = sip + "_" + dip;
                            if(Main.allFlow.all_flow_map.containsKey(sipdip)){
                                if(frame_len > Main.MIN_PACKET_LENGTH) {
                                    Main.allFlow.all_flow_map.get(sipdip).add(second);
                                }
                            }
                            else{
                                if(frame_len > Main.MIN_PACKET_LENGTH){
                                    Flow flow = new Flow(sip, dip);
                                    flow.add(second);
                                    Main.allFlow.all_flow_map.put(sipdip, flow);
                                }
                            }

                            /*count all sipdip*/
                            Main.allFlow.all_sipdip_set.add(sipdip);

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


    public static void analysis_dir(File pcap_dir) throws IOException{
        if(pcap_dir.listFiles()!=null){
            for(File file :pcap_dir.listFiles()){
                if(!file.isHidden()){
                    if(file.getName().contains("pcap")) {
                        analysis_file(file);
                    }
                }
            }
        }
    }


    public static void analysis(String pcapFilePath) throws IOException{
        System.out.println("Start Analysing pcap:...");
        long start, end;
        start = System.currentTimeMillis();
        File input = new File(pcapFilePath);
        if(input.isFile()){
            analysis_file(input);
        }else{
            analysis_dir(input);
        }
        end = System.currentTimeMillis();
        System.out.println("Analysis complete, time used " + (end - start) / 1000 + "s");
        System.out.println("all flow count = " + Main.allFlow.all_sipdip_set.size());
    }


    public static void readAllFlow(String all_flow_path) throws IOException, ClassNotFoundException{
        System.out.println("Start reading allFlow...");
        ObjectInputStream oin = new ObjectInputStream(new FileInputStream(all_flow_path));
        Main.allFlow = (AllFlow) oin.readObject();
        System.out.println("reading success, all flow count = " + Main.allFlow.all_sipdip_set.size());
    }


    public static void writeAllFlow(String all_flow_path) throws IOException{
        System.out.println("Start writing allFlow...");
        ObjectOutputStream oout = new ObjectOutputStream(new FileOutputStream(all_flow_path));
        oout.writeObject(Main.allFlow);
        oout.close();
        System.out.println("Writing allFlow success");
    }
}
