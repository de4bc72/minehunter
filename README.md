# MineHunter
MineHunter is a novel cryptomining traffic detection algorithm based on time series tracking, which can be deployed at the entrance of enterprise networks or campus networks.

**This work is being reviewed by USENIX Security 2020.**

# How to start?
In order to use MineHunter to detect cryptomining traffic, two things must be prepared.
* The **pcap files** that may contain cryptomining traffic
* The **csv file** containing the block creating time associated with the pcap file you want to detect

## Step1. Prepare the pcap files
You can detect a single pcap file or a few pcap files.

## Step2. Prepare the csv file containing the block creating time
You can use *GetBlockCreationTime.py* to generate the csv file.

Here is an example:
```
import GetBlockCreationTime as gbct

stime = 1566987954 # the begining timestamp of the pcap file
etime = 1566988954 # the ending timestamp of the pcap file
out_file = "./block.csv" # the csv file output path

gbct.get_block_creation_time(stime, etime, out_file)
```

## Step3. Modify *config.properties*
```
#the csv file containing the block creating time
blockFilePath=/home/minehunter/block_file/block.csv

#the path containing the pcap files you want to detect
pcapFilePath=/home/data/pcap/
```

## Step4. Detect
In *src/main/java/detect/Main.java*, you can use *detectOnlineSingle()* to detect cryptomining traffic.

Here is an example:
```
//Number of Valid Sub-Intervals
int nodeNumMin = 9;

//Sequence Distance
double meanError = 5.0;

//Entropy Threshold
double entropyThreshold = 2.5;

detectOnlineSingle(pcapFilePath, blockFilePath, nodeNumMin, meanError, entropyThreshold);
```

# Full Datasets
The full datasets used in our paper can be found by following this link: http://157.245.222.177/file/data/anonymize_data/

# License
 This project is licensed under the GPLv3 License
