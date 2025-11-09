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

    /**
     * To create a baseline to in a given root directory when the program is first chekced.
     * Will only run once.
      * @param projectDirectory The root project directory.
     */
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

    /**
     * To monitor any changes for the files or subdirectories in the given project directory.
     * @param projectDir The root project directory.
     */
    public static void monitor(String projectDir) {
        while(true) {
            Map<String, FileInfo> current = scanCurrentDir(projectDir);
            detectModifications(baselineValue, current);
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

    /**
     * Constantly checks for any changes in the given files or subdirectories in the base
     * project directory.
     * @param dirPath The root project directory.
     * @return The state of all the files and subdirectories contained in the project directory.
     */
    public static Map<String, FileInfo> scanCurrentDir(String dirPath) {
        Map<String, FileInfo> current = new HashMap<>();
        File directory = new File(dirPath);
        if ((!directory.exists()) || (!directory.isDirectory())) {
            System.out.println("The provided directory does not exist or is not a directory.");
            return current;
        }
        File[] files = directory.listFiles();
        for (File file : files) {
            if (file.isFile()) {
                String filePath = file.getAbsolutePath();
                long fileSize = file.length();
                long lastUpdated = file.lastModified();
                String permissions = ""; /** retrievePermissions(file); -> to be implemented*/
                FileInfo fileRecord = new FileInfo(filePath, fileSize, lastUpdated, permissions);
                for (String algorithm : Crypto_Algorithms) {
                    long start = System.currentTimeMillis();
                    String hashCode = ""; /** generateFileHashCode(file, algorithm); -> to be implemented **/
                    long end = System.currentTimeMillis();
                    long timeLapse = end - start;
                    switch (algorithm) {
                        case "MD5": {
                            fileRecord.MD5 = hashCode;
                            break;
                        }
                        case "SHA-256": {
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
                current.put(fileRecord.filePath, fileRecord);
            }
            else if (file.isDirectory()) {
                Map<String, FileInfo> subdirMap = scanCurrentDir(file.getAbsolutePath());
                current.putAll(subdirMap);
            }

        }
        return current;
    }

    /**
     * To detect changes of any files in the root project directory and inform the user. While
     * also informing the user of any new files that have been added.
     * @param baseline The state of the project directory when the application is first executed, saved as a baseline.
     * @param current The state of the current project directory. This is consistently checked by the program, compared with the baseline.
     */
    public static void detectModifications(Map<String, FileInfo> baseline, Map<String, FileInfo> current) {
        for(String file: baseline.keySet()) {
            if(!current.containsKey(file)) {
                System.out.println("The file " + file + " has been renamed, moved, or deleted.");
                continue;
            }
            FileInfo oldRecord = baseline.get(file);
            FileInfo newRecord = current.get(file);
            boolean modified = false;
            if(oldRecord.fileSize != newRecord.fileSize) {
                modified = true;
            }
            if(oldRecord.lastUpdated != newRecord.lastUpdated) {
                modified = true;
            }
            if(!oldRecord.permissions.equals(newRecord.permissions)) {
                modified = true;
            }
            if((!oldRecord.MD5.equals(newRecord.MD5)) || (!oldRecord.SHA256.equals(newRecord.SHA256)) || (!oldRecord.SHA512.equals(newRecord.SHA512))) {
                modified = true;
            }
            if(modified) {
                System.out.println("The system has detected that the file: " + file + " has been modified.");
            }
        }
        for(String newFile: current.keySet()) {
            if(!baseline.containsKey(newFile)) {
                System.out.println("A new " + newFile + " has been added to the project directory.");
            }
        }

    }
    public static String generateFileHashCode(File file, String algorithm) {
        return "";
    }
    public static void updateHashStatistics(String algorithm, long timeLapse) {
        return;
    }
    public static void generatePerformanceStats() {
        return;
    }
    public static String retrievePermissions(File file) {
        return "";
    }
    public static void saveBaseline(String baseline) {
        return;
    }
    public static void loadBaseline(String baseline) {
        return;
    }

}
