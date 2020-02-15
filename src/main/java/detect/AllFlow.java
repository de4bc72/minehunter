package detect;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;

public class AllFlow implements Serializable {
    public HashMap<String, Flow> all_flow_map = new HashMap<>();
    public HashSet<String> all_sipdip_set = new HashSet<>();
    public HashSet<String> active_flow_set = new HashSet<>();
}
