package com.project.calendar.mapper;

import com.project.calendar.dto.UserDto;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import java.util.List;

@Mapper
public interface UserMapper {
    public List<UserDto> selectUserList();

    public int setInsertUser(UserDto userDto);

    public UserDto findByLoginId(@Param("id")String id);
}
