package com.retail.app.identity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController2 {

    @GetMapping("/anonymous")
    public String anonymous() {
        return "Привіт! Сюди не пустить, бо в SecurityConfig у нас стоїть anyRequest().authenticated()!";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String userAccess() {
        return "Доступ дозволено! У тебе є роль USER.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String adminAccess() {
        return "Вітаю, Шеф! Доступ дозволено, у тебе є роль ADMIN.";
    }
}