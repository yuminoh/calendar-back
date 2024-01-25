package com.project.calendar.jwt;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 요청이 들어올 때 인증헤더를 보내지 않는 경우 401(unAauthorized) 응답처리를 해줌
 */
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException authException)
        throws IOException, ServletException {
        res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

}
