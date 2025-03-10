package com.example.uauth.service.impl;

import com.example.uauth.config.SsoConfig;
import com.example.uauth.service.SsoService;
import com.example.uauth.service.UserService;
import com.example.uauth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * SSO服务实现类
 */
@Service
public class SsoServiceImpl implements SsoService {

    @Autowired
    private SsoConfig ssoConfig;
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Autowired
    private JwtUtil jwtUtil;
    
    @Autowired
    private UserService userService;
    
    private static final String SSO_TOKEN_PREFIX = "sso:token:";
    
    @Override
    public String handleLoginRequest(String redirectUrl, HttpServletRequest request, HttpServletResponse response) {
        // 检查是否已经登录
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(ssoConfig.getCookieName())) {
                    // 验证Token是否有效
                    Long userId = validateToken(cookie.getValue());
                    if (userId != null) {
                        // Token有效，直接重定向到目标URL
                        return redirectUrl;
                    }
                }
            }
        }
        
        // 未登录，重定向到登录页面
        return ssoConfig.getLoginUrl() + "?redirect=" + redirectUrl;
    }
    
    @Override
    public Long validateToken(String token) {
        if (token == null) {
            return null;
        }
        
        // 从Redis中获取用户ID
        return (Long) redisTemplate.opsForValue().get(SSO_TOKEN_PREFIX + token);
    }
    
    @Override
    public String createToken(Long userId, HttpServletResponse response) {
        // 生成SSO Token
        String token = UUID.randomUUID().toString();
        
        // 将Token存入Redis
        redisTemplate.opsForValue().set(SSO_TOKEN_PREFIX + token, userId, ssoConfig.getTokenTimeout(), TimeUnit.SECONDS);
        
        // 设置Cookie
        Cookie cookie = new Cookie(ssoConfig.getCookieName(), token);
        cookie.setPath("/");
        cookie.setDomain(ssoConfig.getCookieDomain());
        cookie.setMaxAge(ssoConfig.getTokenTimeout().intValue());
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
        
        return token;
    }
    
    @Override
    public String handleLogoutRequest(HttpServletRequest request, HttpServletResponse response) {
        // 获取SSO Token
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(ssoConfig.getCookieName())) {
                    // 从Redis中删除Token
                    redisTemplate.delete(SSO_TOKEN_PREFIX + cookie.getValue());
                    
                    // 清除Cookie
                    Cookie newCookie = new Cookie(ssoConfig.getCookieName(), null);
                    newCookie.setPath("/");
                    newCookie.setDomain(ssoConfig.getCookieDomain());
                    newCookie.setMaxAge(0);
                    response.addCookie(newCookie);
                    
                    break;
                }
            }
        }
        
        // 重定向到登录页面
        return ssoConfig.getLoginUrl();
    }
} 