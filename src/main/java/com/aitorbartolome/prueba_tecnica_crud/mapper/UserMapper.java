package com.aitorbartolome.prueba_tecnica_crud.mapper;

import com.aitorbartolome.prueba_tecnica_crud.dto.UserCreateRequestDTO;
import com.aitorbartolome.prueba_tecnica_crud.dto.UserResponseDTO;
import com.aitorbartolome.prueba_tecnica_crud.entity.User;
import org.mapstruct.Mapper;

import java.util.List;

/**
 * The interface User mapper.
 */
@Mapper(componentModel = "spring")
public interface UserMapper {

    /**
     * To user user.
     *
     * @param requestDTO the request dto
     * @return the user
     */
    User toUser(UserCreateRequestDTO requestDTO);

    /**
     * To user response dto user response dto.
     *
     * @param user the user
     * @return the user response dto
     */
    UserResponseDTO toUserResponseDTO(User user);

    /**
     * To user response dto list list.
     *
     * @param users the users
     * @return the list
     */
    List<UserResponseDTO> toUserResponseDTOList(List<User> users);
}