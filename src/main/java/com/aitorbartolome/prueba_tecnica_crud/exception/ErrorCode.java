package com.aitorbartolome.prueba_tecnica_crud.exception;

/**
 * The enum Error code.
 */
public enum ErrorCode {
    /**
     * The Auth 001.
     */
    AUTH_001("AUTH_001", "Invalid credentials provided"),
    /**
     * The Auth 002.
     */
    AUTH_002("AUTH_002", "User not found"),
    /**
     * The Auth 003.
     */
    AUTH_003("AUTH_003", "Authentication failed"),
    /**
     * The Auth 004.
     */
    AUTH_004("AUTH_004", "Invalid username or password"),

    /**
     * The Jwt 001.
     */
    JWT_001("JWT_001", "Token is expired"),
    /**
     * The Jwt 002.
     */
    JWT_002("JWT_002", "Token is invalid or malformed"),
    /**
     * The Jwt 003.
     */
    JWT_003("JWT_003", "Token signature is invalid"),
    /**
     * The Jwt 004.
     */
    JWT_004("JWT_004", "Token has empty claims"),
    /**
     * The Jwt 005.
     */
    JWT_005("JWT_005", "Unsupported token type"),
    /**
     * The Jwt 006.
     */
    JWT_006("JWT_006", "Bearer token format is required"),
    /**
     * The Jwt 007.
     */
    JWT_007("JWT_007", "Token not provided"),

    /**
     * The User 001.
     */
    USER_001("USER_001", "User not found"),
    /**
     * The User 002.
     */
    USER_002("USER_002", "Username already exists"),
    /**
     * The User 003.
     */
    USER_003("USER_003", "Email already exists"),
    /**
     * The User 004.
     */
    USER_004("USER_004", "User cannot be deleted"),

    /**
     * The Validation 001.
     */
    VALIDATION_001("VALIDATION_001", "Username must be between 3 and 50 characters"),
    /**
     * The Validation 002.
     */
    VALIDATION_002("VALIDATION_002", "Email format is invalid"),
    /**
     * The Validation 003.
     */
    VALIDATION_003("VALIDATION_003", "Password must be at least 8 characters long"),
    /**
     * The Validation 004.
     */
    VALIDATION_004("VALIDATION_004", "Password must contain at least one uppercase letter"),
    /**
     * The Validation 005.
     */
    VALIDATION_005("VALIDATION_005", "Password must contain at least one digit"),
    /**
     * The Validation 006.
     */
    VALIDATION_006("VALIDATION_006", "Password must contain at least one special character"),
    /**
     * The Validation 007.
     */
    VALIDATION_007("VALIDATION_007", "Field cannot be blank"),
    /**
     * The Validation 008.
     */
    VALIDATION_008("VALIDATION_008", "Invalid email format"),

    /**
     * The Authz 001.
     */
    AUTHZ_001("AUTHZ_001", "Unauthorized access"),
    /**
     * The Authz 002.
     */
    AUTHZ_002("AUTHZ_002", "Insufficient permissions for this operation"),

    /**
     * The Resource 001.
     */
    RESOURCE_001("RESOURCE_001", "Resource not found"),
    /**
     * The Resource 002.
     */
    RESOURCE_002("RESOURCE_002", "Duplicate resource"),

    /**
     * The Server 001.
     */
    SERVER_001("SERVER_001", "Internal server error"),
    /**
     * The Server 002.
     */
    SERVER_002("SERVER_002", "Database connection error"),
    /**
     * The Server 003.
     */
    SERVER_003("SERVER_003", "Unexpected error occurred");

    private final String code;
    private final String description;

    ErrorCode(String code, String description) {
        this.code = code;
        this.description = description;
    }

    /**
     * Gets code.
     *
     * @return the code
     */
    public String getCode() {
        return code;
    }

    /**
     * Gets description.
     *
     * @return the description
     */
    public String getDescription() {
        return description;
    }
}