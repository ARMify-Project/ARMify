package armify.services;

import armify.domain.CandidateGroup;
import ghidra.program.model.address.Address;

import java.util.*;

public class MatchingEngine {
    private final DatabaseService db;

    private final List<CandidateGroup> groups = new ArrayList<>();
    private final Map<Long, Integer> gain = new HashMap<>();

    public MatchingEngine(DatabaseService db) {
        this.db = db;
    }

    public void recompute(List<Address> peripheralAddresses, int tolerance) {
        gain.clear();

        /* 0) early out – nothing selected → empty result */
        if (peripheralAddresses == null || peripheralAddresses.isEmpty()) {
            groups.clear();
            return;
        }

        /* 1) SQL hit-list: addr → (device, sig_id)* */
        Map<Long, List<DatabaseService.AddressHit>> hitsByAddr =
                db.queryAddressesFromAddresses(peripheralAddresses);

        /* 2) Build per-device structures */
        int totalSelected = peripheralAddresses.size();
        Map<Integer, int[]> device2sigVector = new HashMap<>();
        Map<Integer, Integer> deviceMatchCount = new HashMap<>();

        // Iterate once over all addresses → populate the maps
        for (int idx = 0; idx < totalSelected; idx++) {
            long addr = peripheralAddresses.get(idx).getOffset();
            List<DatabaseService.AddressHit> hits = hitsByAddr.getOrDefault(addr, List.of());

            for (DatabaseService.AddressHit hit : hits) {
                int dev = hit.deviceId();
                int sig = hit.signatureId();

                // lazily allocate an int[] of size N (default 0 = “missing”)
                int[] vec = device2sigVector.computeIfAbsent(dev, d -> new int[totalSelected]);
                vec[idx] = sig;               // store signature at position idx
                deviceMatchCount.merge(dev, 1, Integer::sum);
            }
        }

        /* 3) Keep only devices that fit tolerance rule */
        List<Integer> candidates = deviceMatchCount.entrySet().stream()
                .filter(e -> (totalSelected - e.getValue()) <= tolerance)
                .map(Map.Entry::getKey)
                .toList();

        /* 4) Bucket identical devices by their “signature vector” */
        Map<String, List<Integer>> bucket = new LinkedHashMap<>();

        for (int dev : candidates) {
            int[] vec = device2sigVector.get(dev);
            // Turn the int[] into a compact key – Arrays.toString() is good enough
            String fp = Arrays.toString(vec);
            bucket.computeIfAbsent(fp, k -> new ArrayList<>()).add(dev);
        }

        /* 5) Build immutable CandidateGroup DTOs, largest buckets first */
        groups.clear();

        bucket.values().stream()
                .sorted(Comparator.<List<Integer>>comparingInt(List::size).reversed())
                .forEach(devList -> {
                    int dev0 = devList.getFirst();
                    int matches = deviceMatchCount.getOrDefault(dev0, 0);

                    List<String> names = devList.stream()
                            .map(db::deviceName)
                            .toList();

                    groups.add(new CandidateGroup(
                            matches,
                            totalSelected,
                            List.copyOf(devList),
                            names
                    ));
                });

        /* 6) Absolute gain per address  ─────────────────────────────────── */
        for (int idx = 0; idx < totalSelected; idx++) {
            long addrOff = peripheralAddresses.get(idx).getOffset();
            int added = 0;

            for (var e : deviceMatchCount.entrySet()) {
                int dev = e.getKey();
                int matches = e.getValue();
                int misses = totalSelected - matches;

                if (misses <= tolerance) {
                    continue;                       // already a candidate
                }
                boolean hit = device2sigVector.get(dev)[idx] != 0;
                int missesIfDrop = misses - (hit ? 0 : 1);

                if (missesIfDrop <= tolerance) {
                    added++;                        // would newly qualify
                }
            }
            gain.put(addrOff, added);
        }
    }

    public List<CandidateGroup> getGroups() {
        return Collections.unmodifiableList(groups);
    }

    public int getGain(Address a) {
        return gain.getOrDefault(a.getOffset(), 0);
    }

    public Optional<DatabaseService.RegisterInfo> getRegisterInfo(int groupIndex, Address addr) {

        if (groupIndex < 0 || groupIndex >= groups.size()) {
            return Optional.empty();
        }
        int firstDevId = groups.get(groupIndex).deviceIds().getFirst();
        return db.registerInfo(firstDevId, addr.getOffset());
    }

    public List<DatabaseService.FieldInfo> regFields(int sigId) {
        return db.regFields(sigId);
    }

    public Optional<Mapping> mappingForGroup(int groupIndex, Address addr) {

        if (groupIndex < 0 || groupIndex >= groups.size()) {
            return Optional.empty();
        }

        List<Integer> devIds = groups.get(groupIndex).deviceIds();
        List<DatabaseService.RegisterInfo> infos = new ArrayList<>();

        for (int devId : devIds) {
            db.registerInfo(devId, addr.getOffset()).ifPresent(infos::add);
        }

        if (infos.isEmpty()) {
            return Optional.of(new Mapping("<missing>", Mapping.State.MISSING, 0));
        }

        Set<String> names = new HashSet<>();
        Set<Integer> sigs = new HashSet<>();
        for (var i : infos) {
            names.add(i.peripheral() + "." + i.register());
            sigs.add(i.sigId());
        }

        if (names.size() == 1 && sigs.size() == 1) {
            var i = infos.getFirst();
            return Optional.of(new Mapping(names.iterator().next(),
                    Mapping.State.OK,
                    i.sigId()));
        }
        return Optional.of(new Mapping("<ambiguous>", Mapping.State.AMBIGUOUS, 0));
    }

    public record Mapping(String name, State state, int sigId) {
        public enum State {OK, MISSING, AMBIGUOUS}
    }
}
