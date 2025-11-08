import java.io.File;
import java.security.MessageDigest;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

// File Integrity Checker Program.
public class FileIntegrityChecker {
    private static final int checkerInterval =  300000;
    private static final String[] Crypto_Algorithms = {"MD5", "SHA-256", "SHA-512"};
    private static Map<String, FileInfo> baselineValue = new HashMap<>();
    private static Map<String, HashInfo> HashCodes = new HashMap<>();
    public static void main(String[] args) {
        System.out.println("Running the file integrity checker program.");
        }
    public static void createBaseline(String projectDirectory) {
        File dir = new File(projectDirectory);
        if((!dir.exists()) || (!dir.isDirectory())) {
            System.out.println("The provided directory does not exist or is not a directory.");
            return;
        }
        File[] files = dir.listFiles();
        for(File file: files) {
            if(file.isFile()) {
                String filePath = file.getAbsolutePath();
                long fileSize = file.length();
                long lastUpdated = file.lastModified();
                String permissions = ""; /** retrievePermissions(file); -> to be implemented*/
                FileInfo fileRecord = new FileInfo(filePath, fileSize, lastUpdated, permissions);
                for(String algorithm: Crypto_Algorithms) {
                    long start = System.currentTimeMillis();
                    String hashCode = ""; /** generateFileHashCode(file, algorithm); -> to be implemented **/
                    long end = System.currentTimeMillis();
                    long timeLapse = end - start;
                    switch(algorithm) {
                        case "MD5" : {
                            fileRecord.MD5 = hashCode;
                            break;
                        }
                        case "SHA-256" : {
                            fileRecord.SHA256 = hashCode;
                            break;
                        }
                        case "SHA-512": {
                            fileRecord.SHA512 = hashCode;
                            break;
                        }
                    }
                    /** updateHashStatistics(algorithm, timeLapse); -> to be implemented **/
                }
                baselineValue.put(fileRecord.filePath, fileRecord);
            }
            else if(file.isDirectory()) {
                createBaseline(file.getAbsolutePath());
            }
        }
    }
    public static void monitor(String projectDir) {
        while(true) {
            Map<String, FileInfo> current = new HashMap<>(); /** scanCurrentDir(projectDir); -> to be implemented **/
            /** indentifyModifications(baselineValue, current); -> to be implemented **/
            /** generatePerformanceStats(); -> to be implemented **/
            try {
                Thread.sleep(checkerInterval);
            }
            catch(InterruptedException e) {
                System.out.println("Timer was interrupted.");
                break;
            }
        }
    }

}
