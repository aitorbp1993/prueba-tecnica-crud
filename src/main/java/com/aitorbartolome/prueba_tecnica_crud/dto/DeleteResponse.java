package com.aitorbartolome.prueba_tecnica_crud.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * The type Delete response.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeleteResponse {

    private String message;
    private UUID id;
    private long timestamp;

    /**
     * Instantiates a new Delete response.
     *
     * @param message the message
     * @param id      the id
     */
    public DeleteResponse(String message, UUID id) {
        this.message = message;
        this.id = id;
        this.timestamp = Instant.now().getEpochSecond();
    }
}
