package armify.ui.events;

import armify.ui.views.ViewType;

public class ViewSelectionEvent {
    private final ViewType viewType;

    public ViewSelectionEvent(ViewType viewType) {
        this.viewType = viewType;
    }

    public ViewType getViewType() {
        return viewType;
    }
}
