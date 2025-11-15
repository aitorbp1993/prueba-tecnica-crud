package com.aitorbartolome.prueba_tecnica_crud.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when JWT token validation fails (401)
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidTokenException extends RuntimeException {

    private final ErrorCode errorCode;

    /**
     * Instantiates a new Invalid token exception.
     *
     * @param message   the message
     * @param errorCode the error code
     */
    public InvalidTokenException(String message, ErrorCode errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Instantiates a new Invalid token exception.
     *
     * @param message   the message
     * @param errorCode the error code
     * @param cause     the cause
     */
    public InvalidTokenException(String message, ErrorCode errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    /**
     * Gets error code.
     *
     * @return the error code
     */
    public ErrorCode getErrorCode() {
        return errorCode;
    }
}