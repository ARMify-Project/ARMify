package armify.services;

import armify.domain.DeviceCandidate;
import armify.domain.MatchResult;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public class DeviceGroupingService {
    private final DatabaseService databaseService;

    public DeviceGroupingService(DatabaseService databaseService) {
        this.databaseService = databaseService;
    }

    public List<MatchResult.DeviceGroup> groupDevices(List<DeviceCandidate> candidates, List<Long> selectedAddresses) {
        Map<String, List<DeviceCandidate>> groupMap = new HashMap<>();

        for (DeviceCandidate candidate : candidates) {
            byte[] fingerprint = calculateCompositeFingerprint(candidate, selectedAddresses);
            String fingerprintKey = Base64.getEncoder().encodeToString(fingerprint);
            
            groupMap.computeIfAbsent(fingerprintKey, k -> new ArrayList<>()).add(candidate);
        }

        return groupMap.values().stream()
            .map(devices -> new MatchResult.DeviceGroup(devices.get(0).getCompositeFingerprint(), devices))
            .collect(Collectors.toList());
    }

    private byte[] calculateCompositeFingerprint(DeviceCandidate candidate, List<Long> selectedAddresses) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            
            // TODO: Get actual hit map for this device
            Map<Long, byte[]> hitMap = getHitMapForDevice(candidate.getDeviceId());
            
            for (Long address : selectedAddresses) {
                byte[] signature = hitMap.getOrDefault(address, new byte[1]); // Missing = single zero byte
                md.update(signature);
            }
            
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 not available", e);
        }
    }

    private Map<Long, byte[]> getHitMapForDevice(int deviceId) {
        // TODO: Implement signature lookup for device
        return new HashMap<>();
    }
}
