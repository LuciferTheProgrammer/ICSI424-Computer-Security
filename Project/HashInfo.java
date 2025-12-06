// Information of hashing algorithm (MD5, SHA-256, and SHA-512).
// Information includes the frequency of the hashing algorithm the total time it
// took to compute all hash codes for all the files in a given directory, total comparisons, and
// the matches made.
public class HashInfo {
    public long count;
    public long totalTime;
    public long totalComparisons;
    public long matchesCount;
}
