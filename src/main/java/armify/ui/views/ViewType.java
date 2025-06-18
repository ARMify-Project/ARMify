package armify.ui.views;

public enum ViewType {
    MMIO_ACCESSES("MMIO Accesses"),
    CANDIDATE_GROUPS("Candidate Groups");

    private final String displayName;

    ViewType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
