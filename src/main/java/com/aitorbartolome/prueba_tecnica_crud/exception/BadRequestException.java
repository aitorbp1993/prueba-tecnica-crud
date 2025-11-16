package com.aitorbartolome.prueba_tecnica_crud.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * The type Bad request exception.
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException {

    private final ErrorCode errorCode;

    /**
     * Instantiates a new Bad request exception.
     *
     * @param message   the message
     * @param errorCode the error code
     */
    public BadRequestException(String message, ErrorCode errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Instantiates a new Bad request exception.
     *
     * @param message   the message
     * @param errorCode the error code
     * @param cause     the cause
     */
    public BadRequestException(String message, ErrorCode errorCode, Throwable cause) {
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