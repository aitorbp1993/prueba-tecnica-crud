package com.aitorbartolome.prueba_tecnica_crud.exception;

/**
 * Exception thrown when JWT validation or parsing fails
 */
public class JwtException extends RuntimeException {

    private final String errorCode;
    private final ErrorCode errorCodeEnum;

    public JwtException(String message, String errorCode) {
        super(message);
        this.errorCode = errorCode;
        this.errorCodeEnum = null;
    }

    public JwtException(String message, String errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.errorCodeEnum = null;
    }

    public JwtException(String message, ErrorCode errorCodeEnum) {
        super(message);
        this.errorCodeEnum = errorCodeEnum;
        this.errorCode = errorCodeEnum.getCode();
    }

    public JwtException(String message, ErrorCode errorCodeEnum, Throwable cause) {
        super(message, cause);
        this.errorCodeEnum = errorCodeEnum;
        this.errorCode = errorCodeEnum.getCode();
    }

    public String getErrorCode() {
        return errorCode;
    }

    public ErrorCode getErrorCodeEnum() {
        return errorCodeEnum;
    }
}