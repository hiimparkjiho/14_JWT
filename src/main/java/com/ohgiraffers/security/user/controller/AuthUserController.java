package com.ohgiraffers.security.user.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("hasAnyAuthority('USER')")
public class AuthUserController {

    @GetMapping("/user")
    public String user(){
        return "user";
    }
}
