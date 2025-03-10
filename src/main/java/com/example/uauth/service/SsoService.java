package com.example.uauth.service;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * SSO服务接口
 */
public interface SsoService {
    
    /**
     * 处理SSO登录请求
     * @param redirectUrl 登录成功后重定向的URL
     * @param request HTTP请求
     * @param response HTTP响应
     * @return 重定向URL
     */
    String handleLoginRequest(String redirectUrl, HttpServletRequest request, HttpServletResponse response);
    
    /**
     * 验证SSO Token
     * @param token SSO Token
     * @return 用户ID
     */
    Long validateToken(String token);
    
    /**
     * 创建SSO Token
     * @param userId 用户ID
     * @param response HTTP响应
     * @return SSO Token
     */
    String createToken(Long userId, HttpServletResponse response);
    
    /**
     * 处理SSO登出请求
     * @param request HTTP请求
     * @param response HTTP响应
     * @return 重定向URL
     */
    String handleLogoutRequest(HttpServletRequest request, HttpServletResponse response);
} 