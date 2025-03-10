package com.example.uauth.controller;

import com.example.uauth.util.CaptchaUtil;
import com.example.uauth.util.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 验证码控制器
 */
@RestController
@RequestMapping("/api/captcha")
public class CaptchaController {

    @Autowired
    private CaptchaUtil captchaUtil;
    
    /**
     * 获取验证码
     */
    @GetMapping("/get")
    public Result<CaptchaUtil.CaptchaResult> getCaptcha() {
        CaptchaUtil.CaptchaResult captchaResult = captchaUtil.generateCaptcha();
        return Result.success(captchaResult);
    }
} 