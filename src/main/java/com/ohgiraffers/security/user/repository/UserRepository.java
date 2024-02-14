package com.ohgiraffers.security.user.repository;

import com.ohgiraffers.security.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByUserId(String id);// 빈 값을 받으면 에러가 나기 때문에 optional 객체를 사용한다.
}
