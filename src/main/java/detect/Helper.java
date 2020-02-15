package detect;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class Helper {
    private static final char[] HEX_CHAR = {'0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    public static String bytesToIp(byte[] src) {
        return (src[0] & 0xff) + "." + (src[1] & 0xff) + "." + (src[2] & 0xff)
                + "." + (src[3] & 0xff);
    }

    public static int binarySearch(List<Long> list,long value){
        int lo = 0;
        int hi = list.size()-1;
        while(lo < hi-1){
            //System.out.println("lo:"+lo);
            //System.out.println("hi:"+hi);
            //System.out.println();
            int mid = (lo + hi)/2;
            long midval = list.get(mid);
            if (midval < value) {
                lo = mid;
            } else if (midval > value)  {
                hi = mid;
            } else {
                return mid;  // value found
            }
        }
        return lo;
    }

    public static long string2Time(String dateString) throws java.text.ParseException {
        DateFormat dateFormat;
        String realTime = dateString.split("\\.")[0];
        dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        dateFormat.setLenient(false);
        Date timeDate = dateFormat.parse(realTime);
        return timeDate.getTime()*1000;//return ns
    }

    public static byte[] intToLittleEndian(long numero) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt((int) numero);
        return bb.array();
    }

    public static short bytesToShort(byte[] input, int offset, boolean littleEndian) {
        ByteBuffer buffer = ByteBuffer.wrap(input,offset,2);
        if(littleEndian){
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
        return buffer.getShort();
    }

    public static int bytesToInt(byte[] input, int offset, boolean littleEndian) {
        ByteBuffer buffer = ByteBuffer.wrap(input,offset,4);
        if(littleEndian){
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
        return buffer.getInt();
    }

    public static long bytesToLong(byte[] input, int offset, boolean littleEndian) {
        ByteBuffer buffer = ByteBuffer.wrap(input,offset,8);
        if(littleEndian){
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
        return buffer.getLong();
    }

    public static String bytesToHexFun1(byte[] bytes) {
        char[] buf = new char[bytes.length * 2];
        int a = 0;
        int index = 0;
        for(byte b : bytes) {
            if(b < 0) {
                a = 256 + b;
            } else {
                a = b;
            }

            buf[index++] = HEX_CHAR[a / 16];
            buf[index++] = HEX_CHAR[a % 16];
        }

        return new String(buf);
    }
}
