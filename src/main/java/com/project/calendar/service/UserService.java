package com.project.calendar.service;

import com.project.calendar.dto.UserDto;

import java.util.List;

public interface UserService {
    public List<UserDto> selectUserList();
}
