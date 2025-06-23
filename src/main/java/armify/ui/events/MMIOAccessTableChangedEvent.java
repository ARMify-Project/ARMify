package armify.ui.events;

import armify.domain.MMIOAccessEntry;

import java.util.List;

public record MMIOAccessTableChangedEvent(List<MMIOAccessEntry> entries) {
}
