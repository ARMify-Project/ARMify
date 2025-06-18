package armify.ui.events;

import armify.domain.MMIOAccessEntry;

import java.util.List;

public class AnalysisCompleteEvent {
    private final List<MMIOAccessEntry> accesses;

    public AnalysisCompleteEvent(List<MMIOAccessEntry> accesses) {
        this.accesses = accesses;
    }

    public List<MMIOAccessEntry> getAccesses() {
        return accesses;
    }
}