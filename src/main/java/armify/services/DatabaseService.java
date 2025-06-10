package armify.services;

import armify.domain.DeviceCandidate;
import java.util.List;
import java.util.Map;

public class DatabaseService {
    
    public Map<Long, List<AddressHit>> queryAddresses(List<Long> addresses) {
        // TODO: Implement SQLite query against addr2dev table
        // String sql = "SELECT a.addr, a.device_id, a.sig_id FROM addr2dev AS a WHERE a.addr IN (?,?,... LIMIT 200)";
        throw new UnsupportedOperationException("Database implementation pending");
    }

    public List<DeviceCandidate> getAllDevices() {
        // TODO: Implement device lookup
        throw new UnsupportedOperationException("Database implementation pending");
    }

    public void close() {
        // TODO: Close database connection
    }

    public static class AddressHit {
        private final long address;
        private final int deviceId;
        private final int signatureId;

        public AddressHit(long address, int deviceId, int signatureId) {
            this.address = address;
            this.deviceId = deviceId;
            this.signatureId = signatureId;
        }

        public long getAddress() { return address; }
        public int getDeviceId() { return deviceId; }
        public int getSignatureId() { return signatureId; }
    }
}
