package com.project.calendar.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

/**
 * JwtTokenFilter.java : 토큰을 파싱하여 유저정보를 가져오고, 토큰이 유효할 경우 해당 유저에게 권한 부여
 * OncePerRequestFilter : HttpRequest의 한번의 요청에 대해 한번만 실행하는 필터(포워딩시에도 이미 실행되었으면 다시 실행 안함)
 * Filter는 어플리케이션의 http요청/응답을 가로채는데 사용
 */
public class JwtTokenFilter extends OncePerRequestFilter {

    // 토큰 검증이 필요 없는 url
    private static final String[] WHITELIST = {
            "/user/signin", // 로그인
            "/user/signup"     // 회원가입
    };
    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer ";

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private final AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain) throws ServletException, IOException {
        String path = req.getRequestURI();

        if (Arrays.stream(WHITELIST).anyMatch(pattern -> antPathMatcher.match(pattern, path))) {
            // 토큰 검증이 필요없는 url은 바로 실행
            filterChain.doFilter(req, res);

            return;
        }

        String accessToken = resolveToken(req);

        try {
            // Access Token 유효성 검사
            if (jwtTokenProvider.validateAccessToken(accessToken)) {
                // 토큰에서 Authentication 객체를 가지고 와서 SecurityContext에 저장
                /**
                 * SecurityContext : Authentication객체가 저장되는 저장소
                 * 이유? 아직 실행되지 않은 filter에서 Authentication객체가 있는지 확인했는데 Authentication객체가 존재하지 않아서
                 * 결국 정상적 요청 프로세스가 진행되지 못하고 error를 냅
                 */
                Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                //throwException
            }
        } catch(HttpClientErrorException e) {
            //throwException
        }

        filterChain.doFilter(req, res);
    }

    private String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader(AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER)) {
            return bearerToken.substring(BEARER.length());
        }
        return null;
    }
}
