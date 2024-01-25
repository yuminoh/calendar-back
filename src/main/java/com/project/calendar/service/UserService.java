package com.project.calendar.service;

import com.project.calendar.dto.UserDto;
import com.project.calendar.jwt.RefreshToken;
import com.project.calendar.request.LoginReq;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface UserService {
    public List<UserDto> selectUserList();

    public int setInsertUser(UserDto userDto);

    public RefreshToken login(LoginReq req);

    public String refreshToken(String accessToken); //추후 RefreshToken 객체로 리턴

    public String logout(String accessToken);
}
