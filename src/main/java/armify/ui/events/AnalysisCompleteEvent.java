package armify.ui.events;

import armify.domain.PeripheralAccess;

import java.util.List;

public class AnalysisCompleteEvent {
    private final List<PeripheralAccess> accesses;

    public AnalysisCompleteEvent(List<PeripheralAccess> accesses) {
        this.accesses = accesses;
    }

    public List<PeripheralAccess> getAccesses() {
        return accesses;
    }
}