package com.aitorbartolome.prueba_tecnica_crud.service.impl;

import com.aitorbartolome.prueba_tecnica_crud.dto.UserCreateRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.UserResponseDTO;
import com.aitorbartolome.prueba_tecnica_crud.entity.User;
import com.aitorbartolome.prueba_tecnica_crud.exception.DuplicateResourceException;
import com.aitorbartolome.prueba_tecnica_crud.exception.ErrorCode;
import com.aitorbartolome.prueba_tecnica_crud.exception.ResourceNotFoundException;
import com.aitorbartolome.prueba_tecnica_crud.mapper.UserMapper;
import com.aitorbartolome.prueba_tecnica_crud.repository.UserRepository;
import com.aitorbartolome.prueba_tecnica_crud.service.UserService;
import com.aitorbartolome.prueba_tecnica_crud.validation.PasswordValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final PasswordValidator passwordValidator;

    @Override
    @Transactional
    public UserResponseDTO createUser(UserCreateRequestDTO userCreateDTO) {
        // Validate password strength
        passwordValidator.validate(userCreateDTO.getPassword());

        // Check for duplicate username
        if (userRepository.existsByUsername(userCreateDTO.getUsername())) {
            throw new DuplicateResourceException(
                    "Username '" + userCreateDTO.getUsername() + "' already exists",
                    ErrorCode.USER_002
            );
        }

        // Check for duplicate email
        if (userRepository.existsByEmail(userCreateDTO.getEmail())) {
            throw new DuplicateResourceException(
                    "Email '" + userCreateDTO.getEmail() + "' is already registered",
                    ErrorCode.USER_003
            );
        }

        // Encode password
        String encodedPassword = passwordEncoder.encode(userCreateDTO.getPassword());

        // Create and save user
        User userToCreate = userMapper.toUser(userCreateDTO);
        userToCreate.setPassword(encodedPassword);

        User savedUser = userRepository.save(userToCreate);

        return userMapper.toUserResponseDTO(savedUser);
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponseDTO> getAllUsers() {
        List<User> users = userRepository.findAll();
        return userMapper.toUserResponseDTOList(users);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDTO getUserById(UUID id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "User not found with id: " + id,
                        ErrorCode.USER_001
                ));

        return userMapper.toUserResponseDTO(user);
    }

    @Override
    @Transactional
    public void deleteUser(UUID id) {
        if (!userRepository.existsById(id)) {
            throw new ResourceNotFoundException(
                    "User not found with id: " + id,
                    ErrorCode.USER_001
            );
        }

        userRepository.deleteById(id);
    }
}