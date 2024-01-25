package com.project.calendar.controller;

import com.project.calendar.dto.UserDto;
import com.project.calendar.jwt.RefreshToken;
import com.project.calendar.request.LoginReq;
import com.project.calendar.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder encoder;

    @RequestMapping(value="/users", method= RequestMethod.GET)
    @ResponseBody
    public Map<String, List<UserDto>> getUserList() {
        Map<String, List<UserDto>> result = new HashMap<>();

        result.put("list", userService.selectUserList());

        return result;
    }

    @RequestMapping(value="/user/signup", method = RequestMethod.POST)
    @ResponseBody
    public int setUser(@RequestBody UserDto userDto) {
        System.out.println("user"+userDto);
        userDto.setUserPw(encoder.encode(userDto.getUserPw()));

        int cnt = userService.setInsertUser(userDto);

        return cnt;
    }

    @RequestMapping(value="/user/signin", method=RequestMethod.POST)
    @ResponseBody
    public Map<String, Object> login(@RequestBody LoginReq req) {
        System.out.println("id, pw"+req.getUserId()+req.getUserPw());
        Map<String, Object> map = new HashMap<>();

        map.put("token", userService.login(req));
        return map;
    }

    @RequestMapping(value="/user/refreshToken", method=RequestMethod.POST)
    @ResponseBody
    public Map<String, Object> refreshToken(HttpServletRequest req) {
        String accessToken = req.getHeader("Authorization").split(" ")[1];
        Map<String, Object> map = new HashMap<>();

        String str = userService.refreshToken(accessToken);

        map.put("result", str);

        return map;
    }

    @RequestMapping(value="/user/signout", method=RequestMethod.POST)
    @ResponseBody
    public Map<String, Object> logout(HttpServletRequest req) {
        String accessToken = req.getHeader("Authorization").split(" ")[1];
        Map<String, Object> map = new HashMap<>();

        map.put("result", userService.logout(accessToken));

        return map;
    }

}
