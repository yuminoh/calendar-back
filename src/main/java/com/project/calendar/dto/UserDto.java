package com.project.calendar.dto;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * UserDetails : security에서 사용자의 정보를 담는 인터페이스
 */
@Getter
@Setter
@ToString
@NoArgsConstructor
@Data
public class UserDto implements UserDetails {

    @Id
    private int no;

    private String userId;

    private String salt;

    private String userPw;

    private String address1;

    private String address2;

    private String email;

    private String tell;

    public UserDto(int no, String userId, String salt, String userPw, String address1, String address2, String email, String tell) {
        this.no = no;
        this.userId = userId;
        this.salt = salt;
        this.userPw = userPw;
        this.address1 = address1;
        this.address2 = address2;
        this.email = email;
        this.tell = tell;
    }

    /**
     * 계정의 권한 목록 return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        return authorities;
    }

    /**
     * 계정의 비밀번호 return
     */
    @Override
    public String getPassword() {
        return this.userPw;
    }

    /**
     * 계정의 고유값(id, email 등) return
     */
    @Override
    public String getUsername() {
        return this.userId;
    }

    /**
     * 계정의 만료여부 return
     * @return true: 만료안됨
     */
    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    /**
     * 계정 잠김여부 return
     * @return true: 잠기지 않음
     */
    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    /**
     * 비밀번호 만료 여부 return
     * @return true: 만료안됨
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    /**
     * 계정 활성화 여부 return
     * @return true: 활성화 됨
     */
    @Override
    public boolean isEnabled() {
        return false;
    }

    public int getNo() {
        return no;
    }

    public String getUserId() {
        return userId;
    }

    public String getSalt() {
        return salt;
    }

    public String getUserPw() {
        return userPw;
    }

    public String getAddress1() {
        return address1;
    }

    public String getAddress2() {
        return address2;
    }

    public String getEmail() {
        return email;
    }

    public String getTell() {
        return tell;
    }

    public void setNo(int no) {
        this.no = no;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public void setUserPw(String userPw) {
        this.userPw = userPw;
    }

    public void setAddress1(String address1) {
        this.address1 = address1;
    }

    public void setAddress2(String address2) {
        this.address2 = address2;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setTell(String tell) {
        this.tell = tell;
    }
}
