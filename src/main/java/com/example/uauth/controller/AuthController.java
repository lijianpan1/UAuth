package com.example.uauth.controller;

import com.example.uauth.dto.LoginRequest;
import com.example.uauth.dto.LoginResponse;
import com.example.uauth.entity.User;
import com.example.uauth.service.UserService;
import com.example.uauth.util.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * 认证控制器
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;
    
    /**
     * 用户登录
     */
    @PostMapping("/login")
    public Result<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        return userService.login(loginRequest);
    }
    
    /**
     * 用户注册
     */
    @PostMapping("/register")
    public Result<User> register(@RequestBody User user) {
        return userService.register(user);
    }
    
    /**
     * 刷新Token
     */
    @PostMapping("/refresh-token")
    public Result<LoginResponse> refreshToken(@RequestParam String refreshToken) {
        return userService.refreshToken(refreshToken);
    }
    
    /**
     * 退出登录
     */
    @PostMapping("/logout")
    public Result<?> logout(@RequestHeader("Authorization") String authorization) {
        String token = authorization.substring(7);
        return userService.logout(token);
    }
} 