package com.aitorbartolome.prueba_tecnica_crud.exception;

/**
 * Exception thrown when JWT validation or parsing fails
 */
public class JwtException extends RuntimeException {

    private final String errorCode;
    private final ErrorCode errorCodeEnum;

    /**
     * Instantiates a new Jwt exception.
     *
     * @param message   the message
     * @param errorCode the error code
     */
    public JwtException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
        this.errorCodeEnum = null;
    }

    /**
     * Instantiates a new Jwt exception.
     *
     * @param message   the message
     * @param errorCode the error code
     * @param cause     the cause
     */
    public JwtException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.errorCodeEnum = null;
    }

    /**
     * Instantiates a new Jwt exception.
     *
     * @param message       the message
     * @param errorCodeEnum the error code enum
     */
    public JwtException(String message, ErrorCode errorCodeEnum) {
        super(message);
        this.errorCodeEnum = errorCodeEnum;
        this.errorCode = errorCodeEnum.getCode();
    }

    /**
     * Instantiates a new Jwt exception.
     *
     * @param message       the message
     * @param errorCodeEnum the error code enum
     * @param cause         the cause
     */
    public JwtException(String message, ErrorCode errorCodeEnum, Throwable cause) {
        super(message, cause);
        this.errorCodeEnum = errorCodeEnum;
        this.errorCode = errorCodeEnum.getCode();
    }

    /**
     * Gets error code.
     *
     * @return the error code
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * Gets error code enum.
     *
     * @return the error code enum
     */
    public ErrorCode getErrorCodeEnum() {
        return errorCodeEnum;
    }
}