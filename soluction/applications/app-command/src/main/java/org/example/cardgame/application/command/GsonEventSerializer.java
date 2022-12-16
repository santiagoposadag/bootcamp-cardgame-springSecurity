package org.example.cardgame.application.command;



import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.serialize.AbstractSerializer;
import org.example.cardgame.generic.serialize.EventSerializer;
import org.springframework.stereotype.Component;

import java.lang.reflect.Type;


@Component
public final class GsonEventSerializer extends AbstractSerializer implements EventSerializer {

    @Override
    public <T extends DomainEvent> T deserialize(String aSerialization, Class<?> aType) {
        return gson.fromJson(aSerialization, (Type) aType);
    }

    @Override
    public String serialize(DomainEvent object) {
        return gson.toJson(object);
    }
}
