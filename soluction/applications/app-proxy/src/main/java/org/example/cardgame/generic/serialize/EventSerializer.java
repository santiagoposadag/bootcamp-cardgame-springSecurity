package org.example.cardgame.generic.serialize;

import org.example.cardgame.generic.DomainEvent;


public interface EventSerializer {
     <T extends DomainEvent> T deserialize(String aSerialization, final Class<?> aType);

     String serialize(DomainEvent object);

}
