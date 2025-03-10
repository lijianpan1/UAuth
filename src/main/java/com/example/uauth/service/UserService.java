package com.example.uauth.service;

import com.example.uauth.entity.User;
import com.example.uauth.dto.LoginRequest;
import com.example.uauth.dto.LoginResponse;
import com.example.uauth.util.Result;

import java.util.List;

/**
 * 用户服务接口
 */
public interface UserService {
    
    /**
     * 用户登录
     * @param loginRequest 登录请求
     * @return 登录结果
     */
    Result<LoginResponse> login(LoginRequest loginRequest);
    
    /**
     * 用户注册
     * @param user 用户信息
     * @return 注册结果
     */
    Result<User> register(User user);
    
    /**
     * 刷新Token
     * @param refreshToken 刷新Token
     * @return 新的Token信息
     */
    Result<LoginResponse> refreshToken(String refreshToken);
    
    /**
     * 退出登录
     * @param token 认证Token
     * @return 退出结果
     */
    Result<?> logout(String token);
    
    /**
     * 根据用户ID获取用户信息
     * @param id 用户ID
     * @return 用户信息
     */
    Result<User> getUserById(Long id);
    
    /**
     * 根据用户名获取用户信息
     * @param username 用户名
     * @return 用户信息
     */
    Result<User> getUserByUsername(String username);
    
    /**
     * 获取用户角色
     * @param userId 用户ID
     * @return 角色代码列表
     */
    Result<List<String>> getUserRoles(Long userId);
    
    /**
     * 获取用户权限
     * @param userId 用户ID
     * @return 权限代码列表
     */
    Result<List<String>> getUserPermissions(Long userId);
    
    /**
     * 修改密码
     * @param userId 用户ID
     * @param oldPassword 旧密码
     * @param newPassword 新密码
     * @return 修改结果
     */
    Result<?> updatePassword(Long userId, String oldPassword, String newPassword);
} 