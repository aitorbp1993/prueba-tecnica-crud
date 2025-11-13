package com.aitorbartolome.prueba_tecnica_crud.service;

import com.aitorbartolome.prueba_tecnica_crud.dto.UserCreateRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.UserResponseDTO;

import java.util.List;
import java.util.UUID;

public interface UserService {

    UserResponseDTO createUser(UserCreateRequestDTO userCreateDTO);

    List<UserResponseDTO> getAllUsers();

    UserResponseDTO getUserById(UUID id);

    void deleteUser(UUID id);
}