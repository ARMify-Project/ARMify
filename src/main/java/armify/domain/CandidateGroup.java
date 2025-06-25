package armify.domain;

import java.util.List;

public record CandidateGroup(int matches,
                             int total,
                             List<Integer> deviceIds,
                             List<String> deviceNames) {
}