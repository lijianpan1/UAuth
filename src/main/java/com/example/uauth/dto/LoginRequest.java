package com.example.uauth.dto;

import java.io.Serializable;

/**
 * 登录请求DTO
 */
public class LoginRequest implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private String username;
    private String password;
    private String captcha;
    private String captchaKey;
    private Boolean rememberMe;
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
    
    public String getCaptcha() {
        return captcha;
    }
    
    public void setCaptcha(String captcha) {
        this.captcha = captcha;
    }
    
    public String getCaptchaKey() {
        return captchaKey;
    }
    
    public void setCaptchaKey(String captchaKey) {
        this.captchaKey = captchaKey;
    }
    
    public Boolean getRememberMe() {
        return rememberMe;
    }
    
    public void setRememberMe(Boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
} 