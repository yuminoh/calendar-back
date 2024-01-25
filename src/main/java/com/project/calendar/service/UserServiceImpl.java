package com.project.calendar.service;

import com.project.calendar.dto.UserDto;
import com.project.calendar.jwt.JwtTokenProvider;
import com.project.calendar.jwt.RefreshToken;
import com.project.calendar.mapper.UserMapper;
import com.project.calendar.request.LoginReq;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpHeaders;

import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Override
    public List<UserDto> selectUserList() {
        return userMapper.selectUserList();
    }

    @Value("${jwt.refresh-token-expired}")
    private Long REFRESH_TOKEN_EXPIRE_TIME;

    @Override
    public int setInsertUser(UserDto userDto) {
        UserDto getUser = userMapper.findByLoginId(userDto.getUserId());

        if (getUser != null) {
            //id 중복
        }

        return userMapper.setInsertUser(userDto);
    }

    @Override
    public RefreshToken login(LoginReq req) {
        UserDto userDetail = userMapper.findByLoginId(req.getUserId());

        if (passwordEncoder.matches(req.getUserPw(), userDetail.getUserPw())) {
            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetail.getUserId(), userDetail.getUserPw());
            String accessToken = jwtTokenProvider.createAccessToken(authentication); // Access Token 발급
            String refreshToken = jwtTokenProvider.createRefreshToken(authentication); // Refresh Token 발급


            RefreshToken token = new RefreshToken(authentication.getName(), accessToken, refreshToken);
            redisTemplate.opsForValue().set("RT:"+req.getUserId(),refreshToken,REFRESH_TOKEN_EXPIRE_TIME, TimeUnit.MILLISECONDS); // redis 캐시에 refrash Token 저장

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.add("Authorization", "Bearer " + token.getAccessToken());
            System.out.println("service-token"+token);
            return token;
        } else {
            return null;
        }
    }

    /**
     * 프론트에서 토큰만료로 error인 경우 리프레쉬 api 호출
     * @param accessToken
     */
    @Override
    public String refreshToken(String accessToken) {
        // refresh토큰 만료시간 계산하여 refresh하는 부분은 생각안하기로
        if (jwtTokenProvider.validateAccessToken(accessToken)) {
            //Long diffTime = jwtTokenProvider.getExpiration(accessToken) / 1000 / 60;

            // accesstoken 5분 이하인지 확인
            //if (diffTime < 5) {
                // refreshtoken 유효성 검사
                //if (jwtTokenProvider.validateRefreshToken(refreshToken)) {
                //}
                // accesstoken 만료시간 5분 이하면 access&refresh 재발급
                String reToken = jwtTokenProvider.refreshAccessToken(accessToken);

                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.add("Authorization", "Bearer " + reToken);
                return reToken;
                //}
        } else {
            // 화면에서 처리
            return "nop0";
        }
    }

    @Override
    public String logout(String accessToken) {
        if (!jwtTokenProvider.validateAccessToken(accessToken)) {
            return "expired";
        }

        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);
        if (redisTemplate.opsForValue().get("RT:"+authentication.getName()) != null) {
            //레디스에서 해당 id-토큰 삭제
            redisTemplate.delete("RT:"+authentication.getName());
        }

        //엑세스 토큰 남은 유효시간
        Long expiration = jwtTokenProvider.getExpiration(accessToken);
        System.out.println("expiration Time: "+expiration);

        //로그아웃 후 유효한 토큰으로 접근가능하기 때문에 만료전 로그아웃된 accesstoken은 블랙리스트로 관리
        redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);

        return "ok";
    }
}
