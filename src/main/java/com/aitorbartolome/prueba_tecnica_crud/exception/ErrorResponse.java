package com.aitorbartolome.prueba_tecnica_crud.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;

/**
 * The type Error response.
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {

    private String timestamp;

    private int status;

    private String error;

    private String message;

    private String path;

    private String code;

    private String details;

    /**
     * Of error response.
     *
     * @param status    the status
     * @param errorCode the error code
     * @param message   the message
     * @param path      the path
     * @return the error response
     */
    public static ErrorResponse of(int status, ErrorCode errorCode, String message, String path) {
        return ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(status)
                .error(errorCode.name())
                .message(message != null ? message : errorCode.getDescription())
                .path(path)
                .code(errorCode.getCode())
                .build();
    }

    /**
     * Factory method with additional details
     *
     * @param status    the status
     * @param errorCode the error code
     * @param message   the message
     * @param path      the path
     * @param details   the details
     * @return the error response
     */
    public static ErrorResponse of(int status, ErrorCode errorCode, String message, String path, String details) {
        return ErrorResponse.builder()
                .timestamp(Instant.now().toString())
                .status(status)
                .error(errorCode.name())
                .message(message != null ? message : errorCode.getDescription())
                .path(path)
                .code(errorCode.getCode())
                .details(details)
                .build();
    }
}