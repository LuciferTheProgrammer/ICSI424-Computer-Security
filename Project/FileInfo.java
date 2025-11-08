// Informative fields about a file or attributes to a file.
public class FileInfo {
    public String filePath;
    public long fileSize;
    public long lastUpdated;
    public String permissions;
    public String MD5;
    public String SHA256;
    public String SHA512;
    public FileInfo(String filePath, long fileSize,long lastUpdated, String permissions){
        this.filePath = filePath;
        this.fileSize = fileSize;
        this.lastUpdated = lastUpdated;
        this.permissions = permissions;
    }
}
