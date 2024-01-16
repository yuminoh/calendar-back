package com.project.calendar.service;

import com.project.calendar.dto.UserDto;
import com.project.calendar.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public List<UserDto> selectUserList() {
        return userMapper.selectUserList();
    }
}
