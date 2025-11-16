package com.aitorbartolome.prueba_tecnica_crud.security.constants;

/**
 * The type Jwt constants.
 */
public class JwtConstants {

    private JwtConstants() {
    }

    /**
     * The constant CLAIM_ROLES.
     */
    public static final String CLAIM_ROLES = "roles";
    /**
     * The constant CLAIM_USER_ID.
     */
    public static final String CLAIM_USER_ID = "user_id";
    /**
     * The constant CLAIM_EMAIL.
     */
    public static final String CLAIM_EMAIL = "email";
    /**
     * The constant CLAIM_TOKEN_TYPE.
     */
    public static final String CLAIM_TOKEN_TYPE = "token_type";

    /**
     * The constant TOKEN_TYPE_ACCESS.
     */
    public static final String TOKEN_TYPE_ACCESS = "ACCESS";
    /**
     * The constant TOKEN_TYPE_REFRESH.
     */
    public static final String TOKEN_TYPE_REFRESH = "REFRESH";

    /**
     * The constant AUTHORIZATION_HEADER.
     */
    public static final String AUTHORIZATION_HEADER = "Authorization";
    /**
     * The constant BEARER_PREFIX.
     */
    public static final String BEARER_PREFIX = "Bearer ";
    /**
     * The constant BEARER_PREFIX_LENGTH.
     */
    public static final int BEARER_PREFIX_LENGTH = 7;

    /**
     * The constant ERROR_TOKEN_EXPIRED.
     */
    public static final String ERROR_TOKEN_EXPIRED = "Token JWT expirado";
    /**
     * The constant ERROR_TOKEN_INVALID.
     */
    public static final String ERROR_TOKEN_INVALID = "Token JWT inválido o malformado";
    /**
     * The constant ERROR_TOKEN_UNSIGNED.
     */
    public static final String ERROR_TOKEN_UNSIGNED = "Token JWT no firmado correctamente";
    /**
     * The constant ERROR_TOKEN_CLAIMS_EMPTY.
     */
    public static final String ERROR_TOKEN_CLAIMS_EMPTY = "Claims del token vacíos";
    /**
     * The constant ERROR_USER_NOT_FOUND.
     */
    public static final String ERROR_USER_NOT_FOUND = "Usuario no encontrado en el sistema";
    /**
     * The constant ERROR_INVALID_TOKEN_TYPE.
     */
    public static final String ERROR_INVALID_TOKEN_TYPE = "Tipo de token inválido";
    /**
     * The constant ERROR_TOKEN_NOT_BEARER.
     */
    public static final String ERROR_TOKEN_NOT_BEARER = "El token debe usar el esquema Bearer";
}
