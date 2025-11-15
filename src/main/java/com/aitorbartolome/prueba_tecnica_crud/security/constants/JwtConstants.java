package com.aitorbartolome.prueba_tecnica_crud.security.constants;

/**
 * Constantes centralizadas para la configuración JWT
 * Facilita el mantenimiento y evita magic strings
 */
public class JwtConstants {

    private JwtConstants() {
        // Clase de utilidad, no se debe instanciar
    }

    // ========== CLAIMS ==========
    public static final String CLAIM_ROLES = "roles";
    public static final String CLAIM_USER_ID = "user_id";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_TOKEN_TYPE = "token_type";

    // ========== TOKEN TYPES ==========
    public static final String TOKEN_TYPE_ACCESS = "ACCESS";
    public static final String TOKEN_TYPE_REFRESH = "REFRESH";

    // ========== HEADER ==========
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final int BEARER_PREFIX_LENGTH = 7;

    // ========== ERRORS ==========
    public static final String ERROR_TOKEN_EXPIRED = "Token JWT expirado";
    public static final String ERROR_TOKEN_INVALID = "Token JWT inválido o malformado";
    public static final String ERROR_TOKEN_UNSIGNED = "Token JWT no firmado correctamente";
    public static final String ERROR_TOKEN_CLAIMS_EMPTY = "Claims del token vacíos";
    public static final String ERROR_USER_NOT_FOUND = "Usuario no encontrado en el sistema";
    public static final String ERROR_INVALID_TOKEN_TYPE = "Tipo de token inválido";
    public static final String ERROR_TOKEN_NOT_BEARER = "El token debe usar el esquema Bearer";
}