package com.example.uauth.controller;

import com.example.uauth.dto.LoginRequest;
import com.example.uauth.dto.LoginResponse;
import com.example.uauth.service.SsoService;
import com.example.uauth.service.UserService;
import com.example.uauth.util.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * SSO控制器
 */
@Controller
@RequestMapping("/api/sso")
public class SsoController {

    @Autowired
    private SsoService ssoService;
    
    @Autowired
    private UserService userService;
    
    /**
     * SSO登录页面
     */
    @GetMapping("/login")
    public String login(@RequestParam(required = false) String redirect, Model model) {
        model.addAttribute("redirect", redirect);
        return "sso/login";
    }
    
    /**
     * 处理SSO登录请求
     */
    @PostMapping("/doLogin")
    public RedirectView doLogin(@RequestBody LoginRequest loginRequest, 
                               @RequestParam(required = false) String redirect,
                               HttpServletRequest request,
                               HttpServletResponse response) {
        // 调用登录服务
        Result<LoginResponse> result = userService.login(loginRequest);
        
        if (result.getCode() == 200) {
            // 登录成功，创建SSO Token
            LoginResponse loginResponse = result.getData();
            ssoService.createToken(loginResponse.getUserId(), response);
            
            // 重定向到目标URL
            return new RedirectView(redirect != null ? redirect : "/");
        } else {
            // 登录失败，重定向回登录页面
            return new RedirectView("/api/sso/login?error=" + result.getMessage());
        }
    }
    
    /**
     * 验证SSO Token
     */
    @GetMapping("/validate")
    @ResponseBody
    public Result<Long> validateToken(@RequestParam String token) {
        Long userId = ssoService.validateToken(token);
        if (userId != null) {
            return Result.success(userId);
        } else {
            return Result.error("无效的Token");
        }
    }
    
    /**
     * SSO登出
     */
    @GetMapping("/logout")
    public RedirectView logout(HttpServletRequest request, HttpServletResponse response) {
        String redirectUrl = ssoService.handleLogoutRequest(request, response);
        return new RedirectView(redirectUrl);
    }
    
    /**
     * 处理SSO客户端请求
     */
    @GetMapping("/auth")
    public RedirectView handleClientAuth(@RequestParam String redirectUrl, 
                                        HttpServletRequest request,
                                        HttpServletResponse response) {
        String targetUrl = ssoService.handleLoginRequest(redirectUrl, request, response);
        return new RedirectView(targetUrl);
    }
} 