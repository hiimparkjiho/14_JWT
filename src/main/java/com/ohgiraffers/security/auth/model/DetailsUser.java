package com.ohgiraffers.security.auth.model;

import com.ohgiraffers.security.user.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class DetailsUser implements UserDetails {
    //db에서 가지고 온 사용자 타입을 security에서 사용할 수 있도록 해주는 과정?

    private User user;

    public DetailsUser() {
    }

    public DetailsUser(Optional<User> user) {
        this.user = user.get();
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    // 권한설정 때문에 쓰는 것
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(role -> authorities.add(() -> role));

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getUserPass();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    /*
    * 계정 만료 여부를 표현하는 매서드로
    * false이면
    * */
    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    /*
    * 잠겨있는 계정을 확인하는 매서드로
    * false이면 해당 계정을 사용할 수 없다.
    *
    * 비밀번호 반복 실패로 일시적인 계정 lock의 경우
    * 혹은 오랜 기간 비 점속으로 휴먼 처리
    * */
    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    /*
    * 탈퇴 계정 여부를 표현하는 매서드
    * false면 햬당 계정을 사용할 수 없다.
    *
    * 보통 데이터 삭제는 즉시 하는 것이 아닌 일정 기간 보관 후 삭제한다.
    * */
    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    /*
    * 계정 비활성화 여부로 사용자가 사용할 수 없는 상태
    * false이면 계정을 사용할 수 없다.
    *
    * 삭제 처리 같은 경우
    * */
    @Override
    public boolean isEnabled() {
        return false;
    }
}
