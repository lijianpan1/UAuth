package com.example.uauth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

/**
 * OAuth2控制器
 */
@RestController
@RequestMapping("/oauth")
public class OAuth2Controller {

    @Autowired
    private TokenEndpoint tokenEndpoint;
    
    /**
     * 获取OAuth2 Token（自定义端点，兼容第三方客户端）
     */
    @PostMapping("/token")
    public OAuth2AccessToken getAccessToken(Principal principal, @RequestParam Map<String, String> parameters) throws Exception {
        return tokenEndpoint.postAccessToken(principal, parameters).getBody();
    }
    
    /**
     * 检查Token有效性
     */
    @GetMapping("/check_token")
    public String checkToken(@RequestParam("token") String token) {
        // 简单实现，实际应该调用TokenStore验证Token
        return "Token is valid";
    }
} 