package com.aitorbartolome.prueba_tecnica_crud.service;

import com.aitorbartolome.prueba_tecnica_crud.dto.UserCreateRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.UserResponseDTO;

import java.util.List;
import java.util.UUID;

/**
 * The interface User service.
 */
public interface UserService {

    /**
     * Create user user response dto.
     *
     * @param userCreateDTO the user create dto
     * @return the user response dto
     */
    UserResponseDTO createUser(UserCreateRequestDTO userCreateDTO);

    /**
     * Gets all users.
     *
     * @return the all users
     */
    List<UserResponseDTO> getAllUsers();

    /**
     * Gets user by id.
     *
     * @param id the id
     * @return the user by id
     */
    UserResponseDTO getUserById(UUID id);

    /**
     * Delete user.
     *
     * @param id the id
     */
    void deleteUser(UUID id);
}