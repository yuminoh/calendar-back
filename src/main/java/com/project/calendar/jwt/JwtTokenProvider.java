package com.project.calendar.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * JwtTokenProvider.java : jwt토큰 생성, 파싱, 유효성 검사
 */
@Slf4j
@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String key;

    @Value("${jwt.refresh-token-expired}")
    private int REFRESH_TOKEN_EXPIRED;

    @Value("${jwt.access-token-expired}")
    private int ACCESS_TOKEN_EXPIRED;

    private static final String KEY_ROLE = "ROLE_USER";

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    private static final String AUTHORIZATION = "Authorization";

    private static final String BEARER = "Bearer";

    public String createAccessToken(Authentication authentication) {
        return createToken(authentication, ACCESS_TOKEN_EXPIRED, key);
    }

    public String createRefreshToken(Authentication authentication) {
        return createToken(authentication, REFRESH_TOKEN_EXPIRED, key);
    }

    /**
     * Claims : 사용자/토큰애 대한 property를 key-value형태로 저장
     * - iss : 토큰 발급자
     * - sub : 토큰 식별값
     * - aud : 토큰 대상자
     * - exp : 토큰 만료 시간
     * - nbf : 토큰 활성 날짜
     * - jat : 토큰 발급 시간
     * - jti : 토큰 발급자가 여러명인 경우 구분 값
     */
    private String createToken(Authentication authentication, long expiredTime, String sckey) {
        // hmacShaKeyFor() : 비밀키 문자열을 바이트 배열로 전달
        Key scretKey = Keys.hmacShaKeyFor(sckey.getBytes(StandardCharsets.UTF_8));
        // getAuthorities() : 사용자가 가진 모든 롤정보(Collection<? extends GrantedAuthority>
        // stream() : 컬렉션(List, Set)반복을 처리하는 기능(없으면 for처리해야됨)
        String authorities = authentication.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining(","));

        long now = new Date().getTime();
        Date expired = new Date(now + expiredTime);

        return Jwts.builder()
                .setIssuedAt(new Date())
                .setExpiration(expired)
                // jwt로 인증할 식별자(postman으로 확인하면 id가 토큰과 같이 data에 담김)
                .setSubject(authentication.getName())
                // 식별값, 롤정보로 claim 생성
                .claim(KEY_ROLE, authorities)
                // 개인키로 암호화
                .signWith(SignatureAlgorithm.HS256, scretKey)
                .compact();
    }

    /**
     * redis에 저장된 id에 해당되는 accesstoken값 update
     */
    public String refreshAccessToken(String accessToken) {
        UserDetails user = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        String refreshToken = (String) redisTemplate.opsForValue().get("RT:" + user.getUsername());
        if (validateRefreshToken(refreshToken)) {
            // 현재 접근한 accesstoken은 bl처리
            Long expirationTM = getExpiration(accessToken);
            redisTemplate.opsForValue().set(accessToken, "logout", expirationTM, TimeUnit.MILLISECONDS);

            Authentication authentication = getAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            return createAccessToken(authentication);
        } else {
            return null;
        }
    }

    /**
     * getAuthentication(): 토큰을 복호화하여 토큰내 정보를 꺼냄
     *
     */
    public Authentication getAuthentication(String token) {
        Key secretKey = Keys.hmacShaKeyFor(key.getBytes());

        try {
            Claims claims = Jwts.parser()
                    // 서명시 사용되었던 key
                    .setSigningKey(secretKey)
                    // key를 가지고 파싱
                    .parseClaimsJws(token)
                    .getBody();

            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            User principal = new User(claims.getSubject(), "", authorities);

            // UsernamePasswordAuthenticationToken : 인증이 끝난 후 SecurityContextHolder에 등록될 Authentication객체
            return new UsernamePasswordAuthenticationToken(principal, token, authorities);
        } catch(ExpiredJwtException e) {
            //
            throw new RuntimeException();
        }
    }

    public boolean validateAccessToken(String accessToken) {
        Key scretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));

        String blToken = (String) redisTemplate.opsForValue().get(accessToken);

        try {
            // 재발급 받으려는 토큰이 블랙리스트가 아니면 발급
            if (blToken == null) {
                // 서명시 사용한 key로 복호화 가능하면 true
                Jwts.parser()
                        .setSigningKey(scretKey)
                        .parseClaimsJws(accessToken);

                return true;
            } else {
                return false;
            }

        } catch (SecurityException | MalformedJwtException e) {
            System.out.println(e.getMessage());
            //throw new ConflictException("Invalid JWT token: {}", ErrorCode.CONFLICT_MEMBER_EXCEPTION);
        } catch (ExpiredJwtException e) {
            //throw new TokenException("토큰이 만료되었습니다.", ErrorCode.TOKEN_EXPIRED_EXCEPTION);
            System.out.println(e.getMessage());
        } catch (IllegalArgumentException e) {
            //throw new ConflictException(String.format(e.getMessage(), ErrorCode.CONFLICT_MEMBER_EXCEPTION));
            System.out.println(e.getMessage());
        }
        return false;
    }

    public boolean validateRefreshToken(String refreshToken) {
        Key secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));

        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(refreshToken);

            return true;
        } catch (Exception e) {
            //
        }
        return false;
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader(AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER)) {
            return bearerToken.substring(BEARER.length());
        }
        return null;
    }

    public Long getExpiration(String accessToken) {
        Key secretKey = Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8));
        Date expiration = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(accessToken).getBody().getExpiration();

        return expiration.getTime() - new Date().getTime();
    }

}
