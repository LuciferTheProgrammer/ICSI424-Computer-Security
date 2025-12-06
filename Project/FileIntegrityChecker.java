import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.util.HexFormat;
import java.io.*;
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;
import javax.swing.JOptionPane;

// File Integrity Checker Program. This program is to ensure the original integrity of files that it originally
// computed hash codes for via 3 different hashing algorithms like the MD5, SHA-256, and SHA-512 are kept.
// The original, first computed, hash codes are stored as the baseline so the program then
// checks the directory containing the target files every 1 minute, here being 60,000 ms. If the original files
// have been removed, deleted, or modified -> i.e. change in attributes such as file size by change in content,
// last modified, or change of permissions the corresponding hash code that would be computed will be compared
// to the baseline and since the 2 hash codes are different an alert will then popup at the user's screen
// to notify them of the change in the specific file.
public class FileIntegrityChecker {
    private static final List<String> alerts = new ArrayList<>();
    private static final int checkerInterval =  60000;
    private enum Crypto_Algorithms {
        MD5("MD5"), SHA_256("SHA-256"), SHA_512("SHA-512");
        private final String algorithm;
        Crypto_Algorithms(String algorithm) {
            this.algorithm = algorithm;
        }
        public String algo_type() {
            return algorithm;
        }
    }
    private static final String logPath = "LoggerEvents.txt";
    private static Map<String, FileInfo> baselineValue = new HashMap<>();
    private static Map<String, HashInfo> HashCodes = new HashMap<>();

    // To run the File Integrity Checker Program.
    public static void main(String[] args) throws Exception {
        FileIntegrityChecker checker = new FileIntegrityChecker();
        String baseline = "Baseline Checker.txt";
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter a project directory to monitor: ");
        String filePath = scanner.nextLine();
        checker.logging("Enter a project directory to monitor: " + filePath);
        File directory = new File(filePath);
        if(!directory.exists() || !directory.isDirectory()) {
            System.out.println("Given directory does not exist. Please choose a valid directory.");
            checker.logging("Given directory does not exist. Please choose a valid directory.");
            System.exit(1);
        }
        for(Crypto_Algorithms algorithm : Crypto_Algorithms.values()) {
            HashInfo hash = new HashInfo();
            HashCodes.put(algorithm.algo_type(), hash);
        }
        boolean target = checker.loadBaseline(baseline);
        String container = directory.getAbsolutePath();
        if(!target) {
            checker.createBaseline(container);
            checker.saveBaseline(baseline);
        }
        checker.monitor(container);
    }

    /**
     * To create a baseline in a given root directory when the program is first checked.
     * Will only run once. The baseline contains the file path, file size, last date modified, permission, and the
     * 3 computed hash values for MD5, SHA-256, and SHA-512 for each of the files in the given directory program is executed.
     * Later used for direct comparison to when files are checked again to ensure no malicious tampering occured and to secure the
     * files' integrity.
     * @param projectDirectory The root project directory.
     */
    private void createBaseline(String projectDirectory) throws Exception {
        File dir = new File(projectDirectory);
        if((!dir.exists()) || (!dir.isDirectory())) {
            System.out.println("The provided directory does not exist or is not a directory.");
            logging("The provided directory does not exist or is not a directory.");
            return;
        }
        File[] files = dir.listFiles();
        if(files == null) {
            System.out.println("System error, cannot list files: " + dir.getAbsolutePath());
            logging("System error, cannot list files: " + dir.getAbsolutePath());
            return;
        }
        for(File file: files) {
            if(file.isFile()) {
                String filePath = file.getAbsolutePath();
                long fileSize = file.length();
                long lastUpdated = file.lastModified();
                String permissions = retrievePermissions(file);
                FileInfo fileRecord = new FileInfo(filePath, fileSize, lastUpdated, permissions);
                for(Crypto_Algorithms algorithm: Crypto_Algorithms.values()) {
                    long start = System.currentTimeMillis();
                    String hashCode = generateFileHashCode(file, algorithm);
                    long end = System.currentTimeMillis();
                    long timeLapse = end - start;
                    switch(algorithm) {
                        case MD5 : {
                            fileRecord.MD5 = hashCode;
                            break;
                        }
                        case SHA_256 : {
                            fileRecord.SHA256 = hashCode;
                            break;
                        }
                        case SHA_512 : {
                            fileRecord.SHA512 = hashCode;
                            break;
                        }
                    }
                    updateHashStatistics(algorithm.algo_type(), timeLapse);
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
     * Again, checks for any suspicious activity that may have altered the files in a given directory
     * every 1 minute.
     * @param projectDir The root project directory.
     */
    private void monitor(String projectDir) throws Exception {
        while(true) {
            Map<String, FileInfo> current = scanCurrentDir(projectDir);
            alerts.clear();
            detectModifications(baselineValue, current);
            popAlerts();
            baselineValue.clear();
            baselineValue.putAll(current);
            saveBaseline("Baseline Checker.txt");
            generatePerformanceStats();
            try {
                Thread.sleep(checkerInterval);
            }
            catch(InterruptedException e) {
                System.out.println("Timer was interrupted.");
                logging("Timer was interrupted.");
                return;
            }
        }
    }

    /**
     * Constantly checks for any changes in the given files or subdirectories in the base
     * project directory. Also saves the time for how long each hash algorithm took to compute the
     * hash value for each file.
     * @param dirPath The root project directory.
     * @return The state of all the files and subdirectories contained in the project directory.
     */
    private Map<String, FileInfo> scanCurrentDir(String dirPath) throws Exception {
        Map<String, FileInfo> current = new HashMap<>();
        File directory = new File(dirPath);
        if ((!directory.exists()) || (!directory.isDirectory())) {
            System.out.println("The provided directory does not exist or is not a directory.");
            logging("The provided directory does not exist or is not a directory.");
            return current;
        }
        File[] files = directory.listFiles();
        if(files == null) {
            System.out.println("System error, cannot list files: " + directory.getAbsolutePath());
            logging("System error, cannot list files: " + directory.getAbsolutePath());
            return current;
        }
        for (File file : files) {
            if (file.isFile()) {
                String filePath = file.getAbsolutePath();
                long fileSize = file.length();
                long lastUpdated = file.lastModified();
                String permissions = retrievePermissions(file);
                FileInfo fileRecord = new FileInfo(filePath, fileSize, lastUpdated, permissions);
                for (Crypto_Algorithms algorithm : Crypto_Algorithms.values()) {
                    long start = System.currentTimeMillis();
                    String hashCode = generateFileHashCode(file, algorithm);
                    long end = System.currentTimeMillis();
                    long timeLapse = end - start;
                    switch (algorithm) {
                        case MD5: {
                            fileRecord.MD5 = hashCode;
                            break;
                        }
                        case SHA_256: {
                            fileRecord.SHA256 = hashCode;
                            break;
                        }
                        case SHA_512: {
                            fileRecord.SHA512 = hashCode;
                            break;
                        }
                    }
                    updateHashStatistics(algorithm.algo_type(), timeLapse);
                }
                current.put(fileRecord.filePath, fileRecord);
                String fName = file.getName();
                System.out.println("Message Digest was created successfully for " + fName + ".");
                logging("Message Digest was created successfully for " + fName + ".");
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
    private void detectModifications(Map<String, FileInfo> baseline, Map<String, FileInfo> current) {
        for(String file: baseline.keySet()) {
            if (!current.containsKey(file)) {
                System.out.println("The file " + file + " has been renamed, moved, or deleted.");
                logging("The file " + file + " has been renamed, moved, or deleted.");
                alerts.add("File: " + file + " was renamed, moved, or deleted.");
                continue;
            }
            FileInfo oldRecord = baseline.get(file);
            FileInfo newRecord = current.get(file);
            if (oldRecord.fileSize != newRecord.fileSize) {
                System.out.println("The system has detected that the file: " + file + " has been modified by change in file size.");
                logging("The system has detected that the file: " + file + " has been modified by change in file size.");
                alerts.add("File size has changed for " + file + ".");
            }
            if (oldRecord.lastUpdated != newRecord.lastUpdated) {
                System.out.println("The system has detected that the file: " + file + " has been modified by change in file last date updated.");
                logging("The system has detected that the file: " + file + " has been modified by change in file last date updated.");
                alerts.add("Last date modified has changed for " + file + ".");
            }
            if (!oldRecord.permissions.equals(newRecord.permissions)) {
                System.out.println("The system has detected that the file: " + file + " has been modified by change in file permissions.");
                logging("The system has detected that the file: " + file + " has been modified by change in file permissions.");
                alerts.add("Permissions has changed for " + file + ".");
            }
            boolean mdMatch = oldRecord.MD5.equals(newRecord.MD5);
            boolean sha256Match = oldRecord.SHA256.equals(newRecord.SHA256);
            boolean sha512Match = oldRecord.SHA512.equals(newRecord.SHA512);
            HashInfo mdStatistics = HashCodes.get("MD5");
            HashInfo sha256Statistics = HashCodes.get("SHA-256");
            HashInfo sha512Statistics = HashCodes.get("SHA-512");
            mdStatistics.totalComparisons++;
            if(mdMatch){
                mdStatistics.matchesCount++;
            }
            sha256Statistics.totalComparisons++;
            if(sha256Match){
                sha256Statistics.matchesCount++;
            }
            sha512Statistics.totalComparisons++;
            if(sha512Match){
                sha512Statistics.matchesCount++;
            }
            if (!mdMatch || !sha256Match|| !sha512Match) {
                System.out.println("The system has detected that the file: " + file + " has been modified by change in file MD value.");
                logging("The system has detected that the file: " + file + " has been modified by change in file MD value.");
                alerts.add("MD value has changed for " + file + ".");
            }
        }
        for (String newFile : current.keySet()) {
            if (!baseline.containsKey(newFile)) {
                System.out.println("A new file " + newFile + " has been added to the project directory.");
                logging("A new file " + newFile + " has been added to the project directory.");
                alerts.add("A new file " + newFile + " has been added.");
            }
        }
    }

    /**
     * This generates hash value for a file, where it can be generated by a different
     * cryptographic hashing algorithm: MD5, SHA-256, or SHA-512.
     * @param file The file to generate a hash value for.
     * @param algorithm The type of cryptographic hashing algorithm.
     * @return The computed hash value for the file.
     * @throws Exception if an error occurs.
     */
    private String generateFileHashCode(File file, Crypto_Algorithms algorithm) throws Exception {
        String hash = "";
        switch (algorithm) {
            case MD5 : {
                hash = hashMD5(file);
                break;
            }
            case SHA_256 : {
                hash = hashSHA256(file);
                break;
            }
            case SHA_512 : {
                hash = hashSHA512(file);
                break;
            }
        }
        return hash;
    }

    /**
     * This updates statistical information for each specific hashing algorithm (MD5, SHA-256, or SHA-512) which
     * include how many times they were used -> based on the number of files, and the total time that each
     * algorithm took to compute the hash codes for all the files in the target directory.
     * @param algorithm The specific hashing algorithm (MD5, SHA-256, or SHA-512).
     * @param timeLapse The total time it took for the hashing algorithm to compute all the hash codes for all the files in a given directory.
     *
     */
    private void updateHashStatistics(String algorithm, long timeLapse) {
        HashInfo statistics = HashCodes.get(algorithm);
        if(statistics == null) {
            HashInfo hashRecord = new HashInfo();
            HashCodes.put(algorithm, hashRecord);
            return;
        }
        statistics.totalTime += timeLapse;
        statistics.count++;
    }

    /**
     * To generate a numerical performance report for each hashing algorithm (MD5, SHA-256, or SHA-512).
     * This performance report generated includes the total count of each hashing algorithm, the total time each
     * algorithm took to compute all the hash values for all the files in a given directory, the average time
     * that each algorithm took to compute a hash code with respect to the total number of files it had to compute it for,
     * and the accuracy of each algorithm to identify if there is match with the baseline hash and current computed hash (100% for all algorithms)
     * and if there is change.
     */
    private void generatePerformanceStats() {
        long averageTime = 0;
        for(String algoType: HashCodes.keySet()) {
            HashInfo statistics = HashCodes.get(algoType);
            if(statistics.count > 0) {
                averageTime = statistics.totalTime / statistics.count;
            }
            else if (statistics.count == 0) {
                averageTime = 0;
            }
            double accuracy =  0.0;
            if(statistics.totalComparisons > 0) {
                accuracy = (statistics.matchesCount * 100.0) / statistics.totalComparisons;
                accuracy = Math.round(accuracy * 100.0) / 100.0;
            }
            System.out.println("The statistics for " + algoType + " algorithm are: " + statistics.count + " in frequency, " + statistics.totalTime + " milliseconds in total time, " + averageTime + " milliseconds in average time, and the accuracy is " + accuracy + "%");
            logging("The statistics for " + algoType + " algorithm are: " + statistics.count + " in frequency, " + statistics.totalTime + " milliseconds in total time, " + averageTime + " milliseconds in average time, and accuracy is " + accuracy + "%");
        }
    }
    /**
     * This retrieves the current permission settings from a file and returns it. Permission may be
     * read, write, or execute.
     * @param file The file to look for permissions from.
     * @return the permission from a file.
     */
    private String retrievePermissions(File file) {
        StringBuilder build = new StringBuilder();
        if(file.canRead()) {
            build.append("r");
        }
        else{
            build.append("-");
        }
        if(file.canWrite()) {
            build.append("w");
        }
        else {
            build.append("-");
        }
        if(file.canExecute()) {
            build.append("x");
        }
        else {
            build.append("-");
        }
        return build.toString();
    }

    /**
     * This saves the current state of the files in a directory into a logger/text file document.
     * Used for later when making comparisons with more current iterations of the file states to check
     * and see if anything was modified. The state information logged includes the file path, file size, last updated,
     * permissions, MD5, SHA-256, and SHA-512.
     * @param baseline of files in a given directory, (original states of files).
     */
    private void saveBaseline(String baseline) {
        Path currentDir = Paths.get("").toAbsolutePath();
        String baseLogDirectory = "File_Integrity_Checker_Baseline";
        Path subdir = currentDir.resolve(baseLogDirectory);
        File dir = new File(subdir.toString());
        if(dir.exists() && dir.isDirectory()) {
            System.out.println("The file directory " + baseLogDirectory + " already exist.");
            logging("The file directory " + baseLogDirectory + " already exist.");
        }
        else {
            System.out.println("The file directory " + baseLogDirectory + " does not exist and will be created.");
            logging("The file directory " + baseLogDirectory + " does not exist and will be created.");
            dir.mkdir();
        }
        Path absDir = dir.toPath();
        Path baseFilePath = absDir.resolve(baseline);
        String basePath = baseFilePath.toString();
        try (FileWriter w = new FileWriter(basePath)){
            for (String file : baselineValue.keySet()) {
                    FileInfo record = baselineValue.get(file);
                String logInfo = String.format("%s|%d|%d|%s|%s|%s|%s\n", record.filePath, record.fileSize, record.lastUpdated, record.permissions, record.MD5, record.SHA256, record.SHA512);
                w.write(logInfo);
            }
        }
        catch(IOException e) {
            System.out.println("File IO error while writing to a file: " + e.getMessage());
            logging("File IO error while writing to a file: " + e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * This loads the baseline states of the files in a given directory into the program during
     * execution.
     * @param baseline The original states of the files, include file path, file size, last updated,
     * permissions, MD5, SHA-256, and SHA-512.
     * @return a flag, true if the baseline exist and was loaded and false if the baseline does not exist.
     */
    private boolean loadBaseline(String baseline) {
        boolean loaded = false;
        Path currentDir = Paths.get("").toAbsolutePath();
        String baseLogDirectory = "File_Integrity_Checker_Baseline";
        Path dir = currentDir.resolve(baseLogDirectory);
        Path subdir = dir.resolve(baseline);
        File baseFile = new File(subdir.toString());
        if(!baseFile.exists()) {
            String filePath = baseFile.getAbsolutePath();
            System.out.println("The file " + filePath + " does not exist.");
            logging("The file " + filePath + " does not exist.");
            return loaded;
        }
        String filePath = baseFile.getAbsolutePath();
        baselineValue.clear();
        try(FileReader reader = new FileReader(filePath);
            BufferedReader buffer = new BufferedReader(reader)) {
                String line;
                while((line = buffer.readLine()) != null) {
                    String[] components = line.split("\\|");
                    int numFields = components.length;
                    if(numFields != 7) {
                        System.out.println("Missing fields on a baseline record has been detected, will skip: " + line + " and continue.");
                        logging("Missing fields on a baseline record has been detected, will skip: " + line + " and continue.");
                        continue;
                    }
                    String file = components[0];
                    long fileSize = Long.parseLong(components[1]);
                    long lastUpdated = Long.parseLong(components[2]);
                    String permissions = components[3];
                    String MD5 = components[4];
                    String SHA256 = components[5];
                    String SHA512 = components[6];
                    FileInfo record = new FileInfo(file, fileSize, lastUpdated, permissions);
                    record.MD5 = MD5;
                    record.SHA256 = SHA256;
                    record.SHA512 = SHA512;
                    baselineValue.put(record.filePath, record);
                }
            }
        catch(IOException e) {
            System.out.println("File IO error while reading from a file: " + e.getMessage());
            logging("File IO error while reading from a file: " + e.getMessage());
            System.exit(-1);
        }
        loaded = true;
        return loaded;
    }

    /**
     * This takes a file, computes and returns a hash value for it using MD5.
     * @param file The hash code to compute for.
     * @return The hash value.
     * @throws NoSuchAlgorithmException if an error occurs.
     * @throws IOException if an error occurs.
     */
    private String hashMD5(File file) throws NoSuchAlgorithmException, IOException {
        String hash = "";
        MessageDigest md = MessageDigest.getInstance("MD5");
        try (FileInputStream fileIS = new FileInputStream(file)) {
            byte[] container = new byte[1024];
            int counter;
            while ((counter = fileIS.read(container)) != -1) {
                md.update(container, 0, counter);
            }
            byte[] code = md.digest();
            hash = HexFormat.of().formatHex(code);
        }
        catch(IOException e) {
            System.out.println("File Not Found.");
            logging("File Not Found.");
            System.exit(-1);
        }

        return hash;
    }

    /**
     * This takes a file, computes and returns a hash value for it using SHA-256.
     * @param file The hash code to compute for.
     * @return The hash value.
     * @throws NoSuchAlgorithmException if an error occurs.
     * @throws IOException if an error occurs.
     */
    private String hashSHA256(File file) throws NoSuchAlgorithmException, IOException {
        String hash = "";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fileIS = new FileInputStream(file)) {
            byte[] container = new byte[1024];
            int counter;
            while ((counter = fileIS.read(container)) != -1) {
                md.update(container, 0, counter);
            }
            byte[] code = md.digest();
            hash = HexFormat.of().formatHex(code);
        }
        catch(IOException e) {
            System.out.println("File Not Found.");
            logging("File Not Found.");
            System.exit(-1);
        }

        return hash;
    }

    /**
     * This takes a file, computes and returns a hash value for it using SHA-512.
     * @param file The hash code to compute for.
     * @return The hash value.
     * @throws NoSuchAlgorithmException if an error occurs.
     * @throws IOException if an error occurs.
     */
    private String hashSHA512(File file) throws NoSuchAlgorithmException, IOException {
        String hash = "";
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        try (FileInputStream fileIS = new FileInputStream(file)) {
            byte[] container = new byte[1024];
            int counter;
            while ((counter = fileIS.read(container)) != -1) {
                md.update(container, 0, counter);
            }
            byte[] code = md.digest();
            hash = HexFormat.of().formatHex(code);
        }
        catch(IOException e) {
            System.out.println("File Not Found.");
            logging("File Not Found.");
            System.exit(-1);
        }
        return hash;
    }

    /**
     * This logs real time events during program execution and saves output to a logger.
     * @param message event messages during program execution.
     */
    private void logging(String message) {
        Path currentDir = Paths.get("").toAbsolutePath();
        String baseLogDirectory = "File_Integrity_Checker_Logger";
        Path dir = currentDir.resolve(baseLogDirectory);
        File dirFile = new File(dir.toString());
        if(!dirFile.exists() || !dirFile.isDirectory()) {
            dirFile.mkdir();
        }
        Path logging = dir.resolve(logPath);
        File logFile = new File(logging.toString());
        String absLogPath = logFile.getAbsolutePath();
        try(FileWriter fw = new FileWriter(absLogPath, true)) {
            fw.write(message + System.lineSeparator());

        }
        catch(IOException e) {
            System.out.println("File IO error while writing to a logger: " + e.getMessage());
            System.exit(-1);
        }
    }

    /**
     * List of popup security alerts to notify user if a file has been modified by a malicious
     * entity or event.
     */
    private void popAlerts() {
        if(alerts.isEmpty()) {
            return;
        }
        else {
            String containerAlerts = String.join("\n", alerts);
            Thread tr = new Thread(() -> JOptionPane.showMessageDialog(null, containerAlerts, "File Integrity Alert Event", JOptionPane.WARNING_MESSAGE));
            tr.start();
            alerts.clear();
        }
    }
}