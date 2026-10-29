package dev.rowstile.conformance;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A message in someone's inbox: anyone signed in may send one, only its recipient reads it. */
@Entity
@Table(schema = "app", name = "inbox")
public class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "sender_id")
    private long senderId;

    @Column(name = "recipient_id")
    private long recipientId;

    private String body;

    protected Message() {}

    public Message(long senderId, long recipientId, String body) {
        this.senderId = senderId;
        this.recipientId = recipientId;
        this.body = body;
    }

    public Long getId() {
        return id;
    }
}
