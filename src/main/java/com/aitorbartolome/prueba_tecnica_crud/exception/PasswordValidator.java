package com.aitorbartolome.prueba_tecnica_crud.validation;

import com.aitorbartolome.prueba_tecnica_crud.exception.BadRequestException;
import com.aitorbartolome.prueba_tecnica_crud.exception.ErrorCode;
import org.springframework.stereotype.Component;

/**
 * Custom password validator
 * Requirements:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one digit
 * - At least one special character
 */
@Component
public class PasswordValidator {

    private static final int MIN_LENGTH = 8;
    private static final String UPPERCASE_REGEX = ".*[A-Z].*";
    private static final String DIGIT_REGEX = ".*\\d.*";
    private static final String SPECIAL_CHAR_REGEX = ".*[!@#$%^&*()_+\\-=\\[\\]{};:'\",.<>?/\\\\|`~].*";

    public void validate(String password) {
        if (password == null || password.isEmpty()) {
            throw new BadRequestException(
                    "Password cannot be blank",
                    ErrorCode.VALIDATION_007
            );
        }

        if (password.length() < MIN_LENGTH) {
            throw new BadRequestException(
                    "Password must be at least " + MIN_LENGTH + " characters long",
                    ErrorCode.VALIDATION_003
            );
        }

        if (!password.matches(UPPERCASE_REGEX)) {
            throw new BadRequestException(
                    "Password must contain at least one uppercase letter (A-Z)",
                    ErrorCode.VALIDATION_004
            );
        }

        if (!password.matches(DIGIT_REGEX)) {
            throw new BadRequestException(
                    "Password must contain at least one digit (0-9)",
                    ErrorCode.VALIDATION_005
            );
        }

        if (!password.matches(SPECIAL_CHAR_REGEX)) {
            throw new BadRequestException(
                    "Password must contain at least one special character (!@#$%^&*...)",
                    ErrorCode.VALIDATION_006
            );
        }
    }
}