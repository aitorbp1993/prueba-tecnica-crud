package com.aitorbartolome.prueba_tecnica_crud.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception thrown when user is authenticated but lacks permissions (403)
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class ForbiddenException extends RuntimeException {

    private final ErrorCode errorCode;

    /**
     * Instantiates a new Forbidden exception.
     *
     * @param message   the message
     * @param errorCode the error code
     */
    public ForbiddenException(String message, ErrorCode errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Instantiates a new Forbidden exception.
     *
     * @param message   the message
     * @param errorCode the error code
     * @param cause     the cause
     */
    public ForbiddenException(String message, ErrorCode errorCode, Throwable cause) {
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