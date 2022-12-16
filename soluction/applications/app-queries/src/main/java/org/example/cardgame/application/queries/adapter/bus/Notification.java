package org.example.cardgame.application.queries.adapter.bus;

import com.google.gson.Gson;

import java.time.Instant;
import java.util.List;


public class Notification {
    private final String type;
    private final String body;
    private final Instant instant;
    private final Long traceId;
    private final Long parentId;
    private final Long spanId;
    private final List<Object> extras;

    public Notification(String type, String body, Long traceId, Long parentId, Long spanId, List<Object> extras) {
        this.type = type;
        this.body = body;
        this.traceId = traceId;
        this.parentId = parentId;
        this.spanId = spanId;
        this.extras = extras;
        this.instant = Instant.now();
    }

    private Notification(){
        this(null,null, null, null, null, null);
    }


    public List<Object> getExtras() {
        return extras;
    }

    public Long getParentId() {
        return parentId;
    }

    public Long getSpanId() {
        return spanId;
    }

    public Long getTraceId() {
        return traceId;
    }

    public String getType() {
        return type;
    }

    public String getBody() {
        return body;
    }

    public Instant getInstant() {
        return instant;
    }

    public Notification deserialize(String aSerialization) {
        return  new Gson().fromJson(aSerialization, Notification.class);
    }

    public String serialize() {
        return new Gson().toJson(this);
    }

    public static Notification from(String aNotification){
        return new Notification().deserialize(aNotification);
    }


    @Override
    public String toString() {
        return "Notification{" +
                "type='" + type + '\'' +
                ", body='" + body + '\'' +
                ", instant=" + instant +
                ", traceId=" + traceId +
                ", parentId=" + parentId +
                ", spanId=" + spanId +
                ", extras=" + extras +
                '}';
    }
}