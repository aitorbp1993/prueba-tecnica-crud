package com.aitorbartolome.prueba_tecnica_crud.service.impl;

import com.aitorbartolome.prueba_tecnica_crud.dto.UserCreateRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.UserResponseDTO;
import com.aitorbartolome.prueba_tecnica_crud.entity.User;
import com.aitorbartolome.prueba_tecnica_crud.exception.DuplicateResourceException;
import com.aitorbartolome.prueba_tecnica_crud.exception.ResourceNotFoundException;
import com.aitorbartolome.prueba_tecnica_crud.mapper.UserMapper;
import com.aitorbartolome.prueba_tecnica_crud.repository.UserRepository;
import com.aitorbartolome.prueba_tecnica_crud.service.UserService;
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


    @Override
    @Transactional
    public UserResponseDTO createUser(UserCreateRequestDTO userCreateDTO) {

        if (userRepository.existsByUsername(userCreateDTO.getUsername())) {
            throw new DuplicateResourceException("El nombre de usuario ya existe");
        }
        if (userRepository.existsByEmail(userCreateDTO.getEmail())) {
            throw new DuplicateResourceException("El email ya está registrado");
        }

        String hashedPassword = passwordEncoder.encode(userCreateDTO.getPassword());

        User userToCreate = userMapper.toUser(userCreateDTO);
        userToCreate.setPassword(hashedPassword);

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
        User user = userRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException("Usuario no encontrado con id: " + id));

        return userMapper.toUserResponseDTO(user);
    }

    @Override
    @Transactional
    public void deleteUser(UUID id) {
        if (!userRepository.existsById(id)) {
            throw new ResourceNotFoundException("Usuario no encontrado con id: " + id);
        }

        userRepository.deleteById(id);
    }
}