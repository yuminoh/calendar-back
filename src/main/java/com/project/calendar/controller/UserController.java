package com.project.calendar.controller;

import com.project.calendar.dto.UserDto;
import com.project.calendar.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @RequestMapping(value="/users", method= RequestMethod.GET)
    @ResponseBody
    public Map<String, List<UserDto>> getUserList() {
        Map<String, List<UserDto>> result = new HashMap<>();

        result.put("list", userService.selectUserList());

        return result;
    }



}
