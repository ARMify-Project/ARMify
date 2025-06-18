package armify.services;

import armify.domain.*;

import java.util.*;

/**
 * Glue code that turns raw MMIO touches into candidate devices and groups.
 * <p>
 * Large parts (DB queries, gain calculation) are intentionally kept in-memory
 * because <strong>&lt; 200</strong> addresses are processed at once – well
 * within normal heap limits.
 */
public class MatchingEngine {

    private final DatabaseService databaseService;
    private final DeviceGroupingService groupingService;

    public MatchingEngine(DatabaseService databaseService,
                          DeviceGroupingService groupingService) {

        this.databaseService = databaseService;
        this.groupingService = groupingService;
    }

    /**
     * Main entry-point used by the UI.
     *
     * @param accesses  full list coming from the disassembly scan
     * @param tolerance k – maximum #misses a device may have
     */
    public MatchResult findCandidates(List<PeripheralAccessEntry> accesses, int tolerance) {

        /* 1. Collect the (unique) addresses the user included in the search. */
        List<Long> selectedAddresses = accesses.stream()
                .filter(PeripheralAccessEntry::isInclude)
                .map(a -> a.getPeripheralAddress().getOffset())
                .distinct()
                .toList();

        /* 2. DB hit list. */
        Map<Long, List<DatabaseService.AddressHit>> hitMap =
                databaseService.queryAddresses(selectedAddresses);

        /* 3. Per-device score. */
        Map<Integer, Integer> deviceScores = calculateDeviceScores(hitMap);

        /* 4. Filter by k. */
        List<DeviceCandidate> candidates =
                buildCandidates(deviceScores, selectedAddresses.size(), tolerance);

        /* 5. Group by composite fingerprint. */
        List<MatchResult.DeviceGroup> groups =
                groupingService.groupDevices(candidates, selectedAddresses);

        /* 6. Absolute gains per address (for the “+” column in the table). */
        Map<Long, Integer> absoluteGains =
                calculateAbsoluteGains(selectedAddresses, hitMap,
                        deviceScores, selectedAddresses.size(), tolerance);

        return new MatchResult(groups, deviceScores, absoluteGains);
    }

    /* --------------------------------------------------------------------- */
    /* helpers                                                               */
    /* --------------------------------------------------------------------- */

    private Map<Integer, Integer> calculateDeviceScores(
            Map<Long, List<DatabaseService.AddressHit>> hitMap) {

        Map<Integer, Integer> scores = new HashMap<>();
        for (List<DatabaseService.AddressHit> hits : hitMap.values()) {
            for (DatabaseService.AddressHit hit : hits) {
                scores.merge(hit.getDeviceId(), 1, Integer::sum);
            }
        }
        return scores;
    }

    private List<DeviceCandidate> buildCandidates(
            Map<Integer, Integer> deviceScores,
            int selectedCount,
            int tolerance) {

        List<DeviceCandidate> out = new ArrayList<>();

        for (var e : deviceScores.entrySet()) {
            int deviceId = e.getKey();
            int score = e.getValue();
            int missCount = selectedCount - score;

            if (missCount <= tolerance) {
                // TODO pull real name + fingerprint from DB
                String deviceName = "Device_" + deviceId;
                byte[] fingerprint = new byte[20];
                out.add(new DeviceCandidate(deviceId, deviceName,
                        score, missCount, fingerprint));
            }
        }
        return out;
    }

    /**
     * Implements the “absolute gain” definition from §2 of your spec.
     */
    private Map<Long, Integer> calculateAbsoluteGains(
            List<Long> selectedAddresses,
            Map<Long, List<DatabaseService.AddressHit>> hitMap,
            Map<Integer, Integer> deviceScores,
            int selectedCount,
            int tolerance) {

        Map<Long, Integer> gains = new HashMap<>();

        /* Build reverse map: device → set of addresses it hits. */
        Map<Integer, Set<Long>> deviceToAddr = new HashMap<>();
        for (var entry : hitMap.entrySet()) {
            long addr = entry.getKey();
            for (var hit : entry.getValue()) {
                deviceToAddr
                        .computeIfAbsent(hit.getDeviceId(), __ -> new HashSet<>())
                        .add(addr);
            }
        }

        for (long addr : selectedAddresses) {
            int added = 0;

            for (var e : deviceScores.entrySet()) {
                int deviceId = e.getKey();
                int score = e.getValue();
                int missCount = selectedCount - score;

                /* Device already qualifies → no change. */
                if (missCount <= tolerance) {
                    continue;
                }

                boolean hitsAddress = deviceToAddr
                        .getOrDefault(deviceId, Set.of())
                        .contains(addr);

                /* If the device was missing > k, dropping a *miss* helps. */
                int missIfDropped = missCount - (hitsAddress ? 0 : 1);

                if (missIfDropped <= tolerance) {
                    added++;
                }
            }
            gains.put(addr, added);
        }
        return gains;
    }
}