package detect;

public class EvaluationPair {
    public double entropy;
    public double error;

    public EvaluationPair(double error, double entropy){
        this.error = error;
        this.entropy = entropy;
    }
}
