package armify.ui.events;

import armify.domain.PeripheralAccessEntry;

import java.util.List;

public class AnalysisCompleteEvent {
    private final List<PeripheralAccessEntry> accesses;

    public AnalysisCompleteEvent(List<PeripheralAccessEntry> accesses) {
        this.accesses = accesses;
    }

    public List<PeripheralAccessEntry> getAccesses() {
        return accesses;
    }
}