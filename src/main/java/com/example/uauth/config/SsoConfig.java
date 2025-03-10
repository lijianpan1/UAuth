package com.example.uauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.util.ArrayList;
import java.util.List;

/**
 * SSO配置类
 */
@Configuration
@PropertySource("classpath:sso.properties")
public class SsoConfig {
    
    @Value("${sso.client-apps}")
    private String clientApps;
    
    @Value("${sso.token-timeout}")
    private Long tokenTimeout;
    
    @Value("${sso.cookie-domain}")
    private String cookieDomain;
    
    @Value("${sso.cookie-name}")
    private String cookieName;
    
    @Value("${sso.login-url}")
    private String loginUrl;
    
    /**
     * 获取注册的SSO客户端应用
     */
    public List<String> getClientAppUrls() {
        List<String> appUrls = new ArrayList<>();
        if (clientApps != null && !clientApps.isEmpty()) {
            String[] apps = clientApps.split(",");
            for (String app : apps) {
                appUrls.add(app.trim());
            }
        }
        return appUrls;
    }
    
    public Long getTokenTimeout() {
        return tokenTimeout;
    }
    
    public String getCookieDomain() {
        return cookieDomain;
    }
    
    public String getCookieName() {
        return cookieName;
    }
    
    public String getLoginUrl() {
        return loginUrl;
    }
} 