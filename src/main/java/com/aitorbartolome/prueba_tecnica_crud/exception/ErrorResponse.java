package com.aitorbartolome.prueba_tecnica_crud.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

/**
 * Detailed error response following option B format
 * Returns timestamp (Z format), status, error type, message, path, and error code
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

    private String timestamp;  // Changed from Instant to String

    private int status;

    private String error;

    private String message;

    private String path;

    private String code;

    private String details;

    /**
     * Factory method to create error response from ErrorCode
     */
    public static ErrorResponse of(int status, ErrorCode errorCode, String message, String path) {
        return ErrorResponse.builder()
                .timestamp(Instant.now().toString())  // Convert to String
                .status(status)
                .error(errorCode.name())
                .message(message != null ? message : errorCode.getDescription())
                .path(path)
                .code(errorCode.getCode())
                .build();
    }

    /**
     * Factory method with additional details
     */
    public static ErrorResponse of(int status, ErrorCode errorCode, String message, String path, String details) {
        return ErrorResponse.builder()
                .timestamp(Instant.now().toString())  // Convert to String
                .status(status)
                .error(errorCode.name())
                .message(message != null ? message : errorCode.getDescription())
                .path(path)
                .code(errorCode.getCode())
                .details(details)
                .build();
    }
}