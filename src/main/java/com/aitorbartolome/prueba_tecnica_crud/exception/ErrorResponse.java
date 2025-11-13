package com.aitorbartolome.prueba_tecnica_crud.exception;

import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;

public record ErrorResponse(
        int statusCode,
        String error,
        String message,
        LocalDateTime timestamp
) {

    public ErrorResponse(HttpStatus status, String message) {
        this(
                status.value(),
                status.getReasonPhrase(),
                message,
                LocalDateTime.now()
        );
    }
}