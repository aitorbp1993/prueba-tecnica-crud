package com.aitorbartolome.prueba_tecnica_crud.exception;

/**
 * Centralized error codes for all exceptions
 * Prefix: AUTH_ (authentication), USER_ (user operations), JWT_ (token), VALIDATION_ (validation)
 */
public enum ErrorCode {
    // ========== AUTHENTICATION (AUTH_XXX) ==========
    AUTH_001("AUTH_001", "Invalid credentials provided"),
    AUTH_002("AUTH_002", "User not found"),
    AUTH_003("AUTH_003", "Authentication failed"),
    AUTH_004("AUTH_004", "Invalid username or password"),

    // ========== JWT / TOKEN (JWT_XXX) ==========
    JWT_001("JWT_001", "Token is expired"),
    JWT_002("JWT_002", "Token is invalid or malformed"),
    JWT_003("JWT_003", "Token signature is invalid"),
    JWT_004("JWT_004", "Token has empty claims"),
    JWT_005("JWT_005", "Unsupported token type"),
    JWT_006("JWT_006", "Bearer token format is required"),
    JWT_007("JWT_007", "Token not provided"),

    // ========== USER OPERATIONS (USER_XXX) ==========
    USER_001("USER_001", "User not found"),
    USER_002("USER_002", "Username already exists"),
    USER_003("USER_003", "Email already exists"),
    USER_004("USER_004", "User cannot be deleted"),

    // ========== VALIDATION (VALIDATION_XXX) ==========
    VALIDATION_001("VALIDATION_001", "Username must be between 3 and 50 characters"),
    VALIDATION_002("VALIDATION_002", "Email format is invalid"),
    VALIDATION_003("VALIDATION_003", "Password must be at least 8 characters long"),
    VALIDATION_004("VALIDATION_004", "Password must contain at least one uppercase letter"),
    VALIDATION_005("VALIDATION_005", "Password must contain at least one digit"),
    VALIDATION_006("VALIDATION_006", "Password must contain at least one special character"),
    VALIDATION_007("VALIDATION_007", "Field cannot be blank"),
    VALIDATION_008("VALIDATION_008", "Invalid email format"),

    // ========== AUTHORIZATION (AUTHZ_XXX) ==========
    AUTHZ_001("AUTHZ_001", "Unauthorized access"),
    AUTHZ_002("AUTHZ_002", "Insufficient permissions for this operation"),

    // ========== RESOURCE (RESOURCE_XXX) ==========
    RESOURCE_001("RESOURCE_001", "Resource not found"),
    RESOURCE_002("RESOURCE_002", "Duplicate resource"),

    // ========== SERVER (SERVER_XXX) ==========
    SERVER_001("SERVER_001", "Internal server error"),
    SERVER_002("SERVER_002", "Database connection error"),
    SERVER_003("SERVER_003", "Unexpected error occurred");

    private final String code;
    private final String description;

    ErrorCode(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getDescription() {
        return description;
    }
}