package com.project.calendar.dto;

import lombok.Data;

@Data
public class UserDto {
    private int no;

    private String user_id;

    private String user_pw;

    private String salt;

    private String address1;

    private String address2;

    private String email;

    private String tell;
}
