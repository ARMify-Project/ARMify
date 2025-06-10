package armify.domain;

import javax.swing.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EventBus {
    private final Map<Class<?>, List<java.util.function.Consumer<Object>>> handlers = new HashMap<>();

    @SuppressWarnings("unchecked")
    public <T> void subscribe(Class<T> eventType, java.util.function.Consumer<T> handler) {
        handlers.computeIfAbsent(eventType, k -> new ArrayList<>())
                .add((java.util.function.Consumer<Object>) handler);
    }

    @SuppressWarnings("unchecked")
    public <T> void publish(T event) {
        Class<?> eventClass = event.getClass();

        List<java.util.function.Consumer<Object>> eventHandlers = handlers.get(eventClass);

        if (eventHandlers != null) {
            for (int i = 0; i < eventHandlers.size(); i++) {
                final java.util.function.Consumer<Object> handler = eventHandlers.get(i);

                SwingUtilities.invokeLater(() -> {
                    handler.accept(event);
                });
            }
        }
    }
}