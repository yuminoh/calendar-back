package com.project.calendar.config;

import com.project.calendar.jwt.AuthEntryPointJwt;
import com.project.calendar.jwt.JwtTokenFilter;
import com.project.calendar.jwt.JwtTokenProvider;
import lombok.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/**
 * SecurityConfig.java : security 환경설정(권한설정, 필터추가 등등)
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    //    요청이 들어올 때 인증헤더를 보내지 않는 경우 401(unAauthorized) 응답처리를 해줌
    //    AuthEntryPointJwt.java 파일 설정 필요
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    /**
     * 왜 Bean주입하는지 : 생성자 어노테이션 @Autowired 대신 직접 생성할 때 사용
     * @Autowired
     * private JwtTokenFilter jwtTokenFilter;
     * 선언해주면 필요할 때 ()없이 사용 가능
     */
    @Bean
    public JwtTokenFilter jwtTokenFilter() {
        return new JwtTokenFilter();
    }

    /**
     * AuthenticationManager : 인증처리하는 filter로 부터 인증처리를 지시받는 클래스
     * id,pw를 Authentication 인증객체에 저장 후 AuthenticationManager 전달
     * AuthenticationConfiguration : 인증에 대한 일반 구성 설정
     * 인증할 값에 대한 유효성 검사
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        // .getAuthenticationManager() = AuthenticationManager의 .authenticate(authRequest) 에소드를 호출하여 인증처리 위임
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * @Autowired
     * private PasswordEncoder passwordEncoder;
     * Bcrypt라는 해시함수를 이용하여 패스워드 암호화
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * WebSecurityCustomizer webSecurityCustomizer() = extends WebSecurityConfigurerAdapter 의 Configure
     * 해당 url은 security 설정 제외
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return webSecurity -> webSecurity.ignoring().requestMatchers("/error");
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /**
         * csrf : 정상적인 사용자가 의도치 않은 위조요청을 보내는 것(위조된 request를 포함한 link등을 사용할 경우 GET요청을 제외하고 수정되는 요청 메소드 차단)
         * rest-api에서는 세션인증과 다르게 stateless하기때문에 서버에 인증정보를 보관하지 않아서 굳이 불필요한 csrf코드 사용이 필요없으므로 disable
         * Stateless - 서버가 클라이언트의 상태를 보존하지 않는 무상태(<->stateful)
         */
        http
                .csrf(AbstractHttpConfigurer::disable).exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(unauthorizedHandler)
                ).
                sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        // 모두 허용
                        .requestMatchers(
                                "/user/signin", // 로그인
                                "/user/signup"
                        ).permitAll()
                        // 그 외는 인증 필요
                        .anyRequest().authenticated())
                // jwt filter 추가(지정 필터 이전에 실행)
                .addFilterBefore(jwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
