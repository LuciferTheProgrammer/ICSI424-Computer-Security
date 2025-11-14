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

// File Integrity Checker Program.
public class FileIntegrityChecker {
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
    public static void main(String[] args) throws Exception {
        String baseline = "Baseline Checker.txt";
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter a project directory to monitor: ");
        String filePath = scanner.nextLine();
        logging("Enter a project directory to monitor: " + filePath);
        File directory = new File(filePath);
        if(!directory.exists() || !directory.isDirectory()) {
            System.out.println("Given directory does not exist. Please choose a valid directory.");
            logging("Given directory does not exist. Please choose a valid directory.");
            System.exit(1);
        }
        for(Crypto_Algorithms algorithm : Crypto_Algorithms.values()) {
            HashInfo hash = new HashInfo();
            HashCodes.put(algorithm.algo_type(), hash);
        }
        FileIntegrityChecker checker = new FileIntegrityChecker();
        boolean target = checker.loadBaseline(baseline);
        String container = directory.getAbsolutePath();
        if(!target) {
            checker.createBaseline(container);
            checker.saveBaseline(baseline);
        }
        checker.monitor(container);
    }

    /**
     * To create a baseline to in a given root directory when the program is first checked.
     * Will only run once.
     * @param projectDirectory The root project directory.
     */
    public void createBaseline(String projectDirectory) throws Exception {
        File dir = new File(projectDirectory);
        if((!dir.exists()) || (!dir.isDirectory())) {
            System.out.println("The provided directory does not exist or is not a directory.");
            logging("The provided directory does not exist or is not a directory.");
            return;
        }
        File[] files = dir.listFiles();
        for(File file: files) {
            if(file.isFile()) {
                String filePath = file.getAbsolutePath();
                long fileSize = file.length();
                long lastUpdated = file.lastModified();
                String permissions = retrievePermissions(file); //to be implemented
                FileInfo fileRecord = new FileInfo(filePath, fileSize, lastUpdated, permissions);
                for(Crypto_Algorithms algorithm: Crypto_Algorithms.values()) {
                    long start = System.currentTimeMillis();
                    String hashCode = generateFileHashCode(file, algorithm); //to be implemented
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
                    updateHashStatistics(algorithm.algo_type(), timeLapse); //to be implemented
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
    public void monitor(String projectDir) throws Exception {
        while(true) {
            Map<String, FileInfo> current = scanCurrentDir(projectDir);
            detectModifications(baselineValue, current);
            baselineValue.clear();
            baselineValue.putAll(current);
            saveBaseline("Baseline Checker.txt");
            generatePerformanceStats(); //to be implemented
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
     * project directory.
     * @param dirPath The root project directory.
     * @return The state of all the files and subdirectories contained in the project directory.
     */
    public Map<String, FileInfo> scanCurrentDir(String dirPath) throws Exception {
        Map<String, FileInfo> current = new HashMap<>();
        File directory = new File(dirPath);
        if ((!directory.exists()) || (!directory.isDirectory())) {
            System.out.println("The provided directory does not exist or is not a directory.");
            logging("The provided directory does not exist or is not a directory.");
            return current;
        }
        File[] files = directory.listFiles();
        for (File file : files) {
            if (file.isFile()) {
                String filePath = file.getAbsolutePath();
                long fileSize = file.length();
                long lastUpdated = file.lastModified();
                String permissions = retrievePermissions(file); //to be implemented
                FileInfo fileRecord = new FileInfo(filePath, fileSize, lastUpdated, permissions);
                for (Crypto_Algorithms algorithm : Crypto_Algorithms.values()) {
                    long start = System.currentTimeMillis();
                    String hashCode = generateFileHashCode(file, algorithm); //to be implemented
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
                    updateHashStatistics(algorithm.algo_type(), timeLapse); //to be implemented
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
    public void detectModifications(Map<String, FileInfo> baseline, Map<String, FileInfo> current) {
        for(String file: baseline.keySet()) {
            if (!current.containsKey(file)) {
                System.out.println("The file " + file + " has been renamed, moved, or deleted.");
                logging("The file " + file + " has been renamed, moved, or deleted.");
                continue;
            }
            FileInfo oldRecord = baseline.get(file);
            FileInfo newRecord = current.get(file);
            if (oldRecord.fileSize != newRecord.fileSize) {
                System.out.println("The system has detected that the file: " + file + " has been modified by change in file size.");
                logging("The system has detected that the file: " + file + " has been modified by change in file size.");

            }
            if (oldRecord.lastUpdated != newRecord.lastUpdated) {
                System.out.println("The system has detected that the file: " + file + " has been modified by change in file last date updated.");
                logging("The system has detected that the file: " + file + " has been modified by change in file last date updated.");

            }
            if (!oldRecord.permissions.equals(newRecord.permissions)) {
                System.out.println("The system has detected that the file: " + file + " has been modified by change in file permissions.");
                logging("The system has detected that the file: " + file + " has been modified by change in file permissions.");

            }
            if ((!oldRecord.MD5.equals(newRecord.MD5)) || (!oldRecord.SHA256.equals(newRecord.SHA256)) || (!oldRecord.SHA512.equals(newRecord.SHA512))) {
                System.out.println("The system has detected that the file: " + file + " has been modified by change in file MD value.");
                logging("The system has detected that the file: " + file + " has been modified by change in file MD value.");
            }
        }
        for (String newFile : current.keySet()) {
            if (!baseline.containsKey(newFile)) {
                System.out.println("A new " + newFile + " has been added to the project directory.");
                logging("A new " + newFile + " has been added to the project directory.");
            }
        }
    }

    public String generateFileHashCode(File file, Crypto_Algorithms algorithm) throws Exception {
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

    public void updateHashStatistics(String algorithm, long timeLapse) {
        HashInfo statistics = HashCodes.get(algorithm);
        if(statistics == null) {
            HashInfo hashRecord = new HashInfo();
            HashCodes.put(algorithm, hashRecord);
            return;

        }
        statistics.totalTime += timeLapse;
        statistics.count++;
    }
    public void generatePerformanceStats() {
        long averageTime = 0;
        for(String algoType: HashCodes.keySet()) {
            HashInfo statistics = HashCodes.get(algoType);
            if(statistics.count > 0) {
                averageTime = statistics.totalTime / statistics.count;
            }
            else if (statistics.count == 0) {
                averageTime = 0;
            }
            System.out.println("The statistics for " + algoType + " algorithm are: " + statistics.count + " in frequency, " + statistics.totalTime + " milliseconds in total time, and " + averageTime + " milliseconds in average time.");
            logging("The statistics for " + algoType + " algorithm are: " + statistics.count + " in frequency, " + statistics.totalTime + " milliseconds in total time, and " + averageTime + " milliseconds in average time.");
        }
    }
    public String retrievePermissions(File file) {
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
    public void saveBaseline(String baseline) {
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
    public boolean loadBaseline(String baseline) {
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

    private String hashMD5(File file) throws NoSuchAlgorithmException, IOException {
        String hash = "";
        MessageDigest md = MessageDigest.getInstance("MD5");
        System.out.println("Message Digest using MD5 was created successfully.");
        logging("Message Digest using MD5 was created successfully.");
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

    private String hashSHA256(File file) throws NoSuchAlgorithmException, IOException {
        String hash = "";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        System.out.println("Message Digest using SHA_256 was created successfully.");
        logging("Message Digest using SHA_256 was created successfully.");
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

    private String hashSHA512(File file) throws NoSuchAlgorithmException, IOException {
        String hash = "";
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        System.out.println("Message Digest using SHA_512 was created successfully.");
        logging("Message Digest using SHA_512 was created successfully.");
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

    private static void logging(String message) {
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
}