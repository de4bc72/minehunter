package detect;

public class MatchPairData {
    public int matchPos;
    public long blockTimestamp;
    public long matchTimestamp;

    public MatchPairData(int matchPos, long blockTimestamp, long matchTimestamp){
        this.matchPos = matchPos;
        this.blockTimestamp = blockTimestamp;
        this.matchTimestamp = matchTimestamp;
    }
}
