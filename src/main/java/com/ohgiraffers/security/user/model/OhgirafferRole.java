package com.ohgiraffers.security.user.model;

public enum OhgirafferRole {

    USER("USER"),
    ADMIN("ADMIN"),
    ALL("USER,ADMIN");

    private String role;

    OhgirafferRole(String role){
        this.role = role;
    }

    public String getRole() {
        return role;
    }

    @Override
    public String toString() {
        return "OhgirafferRole{" +
                "role='" + role + '\'' +
                '}';
    }
}
