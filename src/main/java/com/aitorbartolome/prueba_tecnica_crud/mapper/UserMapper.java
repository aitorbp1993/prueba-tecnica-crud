package com.aitorbartolome.prueba_tecnica_crud.mapper;

import com.aitorbartolome.prueba_tecnica_crud.dto.UserCreateRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.UserResponseDTO;
import com.aitorbartolome.prueba_tecnica_crud.entity.User;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper {

    User toUser(UserCreateRequestDTO requestDTO);

    UserResponseDTO toUserResponseDTO(User user);

    List<UserResponseDTO> toUserResponseDTOList(List<User> users);
}