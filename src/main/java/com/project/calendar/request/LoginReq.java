package com.project.calendar.request;

import lombok.*;

@ToString
@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class LoginReq {
    private String userId;

    private String userPw;

    public String getUserId() {
        return userId;
    }

    public String getUserPw() {
        return userPw;
    }
}
