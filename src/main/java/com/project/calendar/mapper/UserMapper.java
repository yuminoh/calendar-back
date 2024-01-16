package com.project.calendar.mapper;

import com.project.calendar.dto.UserDto;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface UserMapper {
    public List<UserDto> selectUserList();
}
