package armify.domain;

public class DeviceCandidate {
    private final int deviceId;
    private final String deviceName;
    private final int score;
    private final int missCount;
    private final byte[] compositeFingerprint;

    public DeviceCandidate(int deviceId, String deviceName, int score, int missCount, byte[] compositeFingerprint) {
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.score = score;
        this.missCount = missCount;
        this.compositeFingerprint = compositeFingerprint;
    }

    public int getDeviceId() { return deviceId; }
    public String getDeviceName() { return deviceName; }
    public int getScore() { return score; }
    public int getMissCount() { return missCount; }
    public byte[] getCompositeFingerprint() { return compositeFingerprint; }

    public boolean isCandidate(int tolerance) {
        return missCount <= tolerance;
    }
}
