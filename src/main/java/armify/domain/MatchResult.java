package armify.domain;

import java.util.List;
import java.util.Map;

public class MatchResult {
    private final List<DeviceGroup> groups;
    private final Map<Integer, Integer> deviceScores;
    private final Map<Long, Integer> absoluteGains;

    public MatchResult(List<DeviceGroup> groups, Map<Integer, Integer> deviceScores, Map<Long, Integer> absoluteGains) {
        this.groups = groups;
        this.deviceScores = deviceScores;
        this.absoluteGains = absoluteGains;
    }

    public List<DeviceGroup> getGroups() { return groups; }
    public Map<Integer, Integer> getDeviceScores() { return deviceScores; }
    public Map<Long, Integer> getAbsoluteGains() { return absoluteGains; }

    public static class DeviceGroup {
        private final byte[] fingerprint;
        private final List<DeviceCandidate> devices;
        private final String representativeName;

        public DeviceGroup(byte[] fingerprint, List<DeviceCandidate> devices) {
            this.fingerprint = fingerprint;
            this.devices = devices;
            this.representativeName = devices.isEmpty() ? "Unknown" : devices.get(0).getDeviceName();
        }

        public byte[] getFingerprint() { return fingerprint; }
        public List<DeviceCandidate> getDevices() { return devices; }
        public String getRepresentativeName() { return representativeName; }
        public int size() { return devices.size(); }
    }
}
