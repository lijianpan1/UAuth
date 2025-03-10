package com.example.uauth.controller;

import com.example.uauth.entity.User;
import com.example.uauth.service.UserService;
import com.example.uauth.util.JwtUtil;
import com.example.uauth.util.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户控制器
 */
@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserService userService;
    
    @Autowired
    private JwtUtil jwtUtil;
    
    /**
     * 获取当前用户信息
     */
    @GetMapping("/info")
    public Result<User> getCurrentUser(@RequestHeader("Authorization") String authorization) {
        String token = authorization.substring(7);
        Long userId = jwtUtil.getUserIdFromToken(token);
        return userService.getUserById(userId);
    }
    
    /**
     * 获取用户角色
     */
    @GetMapping("/roles")
    public Result<List<String>> getUserRoles(@RequestHeader("Authorization") String authorization) {
        String token = authorization.substring(7);
        Long userId = jwtUtil.getUserIdFromToken(token);
        return userService.getUserRoles(userId);
    }
    
    /**
     * 获取用户权限
     */
    @GetMapping("/permissions")
    public Result<List<String>> getUserPermissions(@RequestHeader("Authorization") String authorization) {
        String token = authorization.substring(7);
        Long userId = jwtUtil.getUserIdFromToken(token);
        return userService.getUserPermissions(userId);
    }
    
    /**
     * 修改密码
     */
    @PostMapping("/update-password")
    public Result<?> updatePassword(@RequestHeader("Authorization") String authorization,
                                   @RequestParam String oldPassword,
                                   @RequestParam String newPassword) {
        String token = authorization.substring(7);
        Long userId = jwtUtil.getUserIdFromToken(token);
        return userService.updatePassword(userId, oldPassword, newPassword);
    }
    
    /**
     * 获取用户列表（需要管理员权限）
     */
    @GetMapping("/list")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public Result<List<User>> getUserList() {
        // 这里简化处理，实际应该从数据库查询
        return Result.error("功能未实现");
    }
} 