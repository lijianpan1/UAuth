package com.example.uauth.service.impl;

import com.example.uauth.dto.LoginRequest;
import com.example.uauth.dto.LoginResponse;
import com.example.uauth.entity.User;
import com.example.uauth.service.UserService;
import com.example.uauth.util.CaptchaUtil;
import com.example.uauth.util.JwtUtil;
import com.example.uauth.util.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 用户服务实现类
 */
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    private JwtUtil jwtUtil;
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Autowired
    private CaptchaUtil captchaUtil;
    
    // 模拟数据库，实际项目中应该使用MyBatis或JPA访问数据库
    private static final List<User> userList = new ArrayList<>();
    
    static {
        // 初始化一个管理员用户
        User admin = new User();
        admin.setId(1L);
        admin.setUsername("admin");
        admin.setPassword("$2a$10$ixlPY3AAd4ty1l6E2IsQ9OFZi2ba9ZQE0bP7RFcGIWNhyFrrT3YUi"); // 密码: 123456
        admin.setEmail("admin@example.com");
        admin.setPhone("13800138000");
        admin.setRealName("系统管理员");
        admin.setStatus(1);
        admin.setCreateTime(new Date());
        admin.setUpdateTime(new Date());
        userList.add(admin);
    }

    @Override
    public Result<LoginResponse> login(LoginRequest loginRequest) {
        // 1. 验证验证码
        if (loginRequest.getCaptcha() != null && loginRequest.getCaptchaKey() != null) {
            boolean captchaValid = captchaUtil.verifyCaptcha(loginRequest.getCaptchaKey(), loginRequest.getCaptcha());
            if (!captchaValid) {
                return Result.error("验证码错误或已过期");
            }
        } else {
            return Result.error("请输入验证码");
        }
        
        // 2. 验证用户名和密码
        User user = null;
        for (User u : userList) {
            if (u.getUsername().equals(loginRequest.getUsername())) {
                user = u;
                break;
            }
        }
        
        if (user == null) {
            return Result.error("用户名不存在");
        }
        
        if (user.getStatus() == 0) {
            return Result.error("账号已被禁用");
        }
        
        // 验证密码
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            return Result.error("密码错误");
        }
        
        // 3. 生成Token
        String token = jwtUtil.generateToken(user.getUsername(), user.getId());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername(), user.getId());
        
        // 4. 更新用户最后登录时间
        user.setLastLoginTime(new Date());
        
        // 5. 将Token存入Redis，设置过期时间
        redisTemplate.opsForValue().set("token:" + token, user.getId(), 24, TimeUnit.HOURS);
        redisTemplate.opsForValue().set("refreshToken:" + refreshToken, user.getId(), 7, TimeUnit.DAYS);
        
        // 6. 如果需要记住我功能，延长Token过期时间
        if (loginRequest.getRememberMe() != null && loginRequest.getRememberMe()) {
            redisTemplate.expire("token:" + token, 7, TimeUnit.DAYS);
        }
        
        // 7. 构建登录响应
        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setToken(token);
        loginResponse.setRefreshToken(refreshToken);
        loginResponse.setExpireTime(System.currentTimeMillis() + 24 * 60 * 60 * 1000); // 24小时
        loginResponse.setUserId(user.getId());
        loginResponse.setUsername(user.getUsername());
        loginResponse.setRealName(user.getRealName());
        
        // 获取用户角色和权限
        List<String> roles = getUserRoles(user.getId()).getData();
        List<String> permissions = getUserPermissions(user.getId()).getData();
        loginResponse.setRoles(roles);
        loginResponse.setPermissions(permissions);
        
        return Result.success("登录成功", loginResponse);
    }

    @Override
    public Result<User> register(User user) {
        // 1. 检查用户名是否已存在
        for (User u : userList) {
            if (u.getUsername().equals(user.getUsername())) {
                return Result.error("用户名已存在");
            }
        }
        
        // 2. 设置用户信息
        user.setId((long) (userList.size() + 1));
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setStatus(1);
        user.setCreateTime(new Date());
        user.setUpdateTime(new Date());
        
        // 3. 保存用户
        userList.add(user);
        
        // 4. 返回结果，不返回密码
        user.setPassword(null);
        return Result.success("注册成功", user);
    }

    @Override
    public Result<LoginResponse> refreshToken(String refreshToken) {
        // 1. 验证刷新Token是否有效
        if (jwtUtil.isTokenExpired(refreshToken)) {
            return Result.error("刷新Token已过期");
        }
        
        // 2. 从Redis中获取用户ID
        Long userId = (Long) redisTemplate.opsForValue().get("refreshToken:" + refreshToken);
        if (userId == null) {
            return Result.error("刷新Token无效");
        }
        
        // 3. 获取用户信息
        User user = null;
        for (User u : userList) {
            if (u.getId().equals(userId)) {
                user = u;
                break;
            }
        }
        
        if (user == null) {
            return Result.error("用户不存在");
        }
        
        // 4. 生成新的Token
        String newToken = jwtUtil.generateToken(user.getUsername(), user.getId());
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getUsername(), user.getId());
        
        // 5. 删除旧的Token
        redisTemplate.delete("refreshToken:" + refreshToken);
        
        // 6. 将新Token存入Redis
        redisTemplate.opsForValue().set("token:" + newToken, user.getId(), 24, TimeUnit.HOURS);
        redisTemplate.opsForValue().set("refreshToken:" + newRefreshToken, user.getId(), 7, TimeUnit.DAYS);
        
        // 7. 构建响应
        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setToken(newToken);
        loginResponse.setRefreshToken(newRefreshToken);
        loginResponse.setExpireTime(System.currentTimeMillis() + 24 * 60 * 60 * 1000);
        loginResponse.setUserId(user.getId());
        loginResponse.setUsername(user.getUsername());
        loginResponse.setRealName(user.getRealName());
        
        // 获取用户角色和权限
        List<String> roles = getUserRoles(user.getId()).getData();
        List<String> permissions = getUserPermissions(user.getId()).getData();
        loginResponse.setRoles(roles);
        loginResponse.setPermissions(permissions);
        
        return Result.success("刷新Token成功", loginResponse);
    }

    @Override
    public Result<?> logout(String token) {
        // 1. 从Redis中删除Token
        redisTemplate.delete("token:" + token);
        return Result.success("退出登录成功");
    }

    @Override
    public Result<User> getUserById(Long id) {
        // 查找用户
        User user = null;
        for (User u : userList) {
            if (u.getId().equals(id)) {
                user = u;
                break;
            }
        }
        
        if (user == null) {
            return Result.error("用户不存在");
        }
        
        // 不返回密码
        User result = new User();
        result.setId(user.getId());
        result.setUsername(user.getUsername());
        result.setEmail(user.getEmail());
        result.setPhone(user.getPhone());
        result.setRealName(user.getRealName());
        result.setStatus(user.getStatus());
        result.setCreateTime(user.getCreateTime());
        result.setUpdateTime(user.getUpdateTime());
        result.setLastLoginTime(user.getLastLoginTime());
        
        return Result.success(result);
    }

    @Override
    public Result<User> getUserByUsername(String username) {
        // 查找用户
        User user = null;
        for (User u : userList) {
            if (u.getUsername().equals(username)) {
                user = u;
                break;
            }
        }
        
        if (user == null) {
            return Result.error("用户不存在");
        }
        
        // 不返回密码
        User result = new User();
        result.setId(user.getId());
        result.setUsername(user.getUsername());
        result.setEmail(user.getEmail());
        result.setPhone(user.getPhone());
        result.setRealName(user.getRealName());
        result.setStatus(user.getStatus());
        result.setCreateTime(user.getCreateTime());
        result.setUpdateTime(user.getUpdateTime());
        result.setLastLoginTime(user.getLastLoginTime());
        
        return Result.success(result);
    }

    @Override
    public Result<List<String>> getUserRoles(Long userId) {
        // 模拟获取用户角色
        List<String> roles = new ArrayList<>();
        if (userId == 1L) {
            roles.add("ROLE_ADMIN");
        } else {
            roles.add("ROLE_USER");
        }
        return Result.success(roles);
    }

    @Override
    public Result<List<String>> getUserPermissions(Long userId) {
        // 模拟获取用户权限
        List<String> permissions = new ArrayList<>();
        if (userId == 1L) {
            permissions.add("sys:user:view");
            permissions.add("sys:user:add");
            permissions.add("sys:user:edit");
            permissions.add("sys:user:delete");
            permissions.add("sys:role:view");
            permissions.add("sys:role:add");
            permissions.add("sys:role:edit");
            permissions.add("sys:role:delete");
            permissions.add("sys:permission:view");
            permissions.add("sys:permission:add");
            permissions.add("sys:permission:edit");
            permissions.add("sys:permission:delete");
        } else {
            permissions.add("sys:user:view");
        }
        return Result.success(permissions);
    }

    @Override
    public Result<?> updatePassword(Long userId, String oldPassword, String newPassword) {
        // 查找用户
        User user = null;
        for (User u : userList) {
            if (u.getId().equals(userId)) {
                user = u;
                break;
            }
        }
        
        if (user == null) {
            return Result.error("用户不存在");
        }
        
        // 验证旧密码
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            return Result.error("旧密码错误");
        }
        
        // 更新密码
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setUpdateTime(new Date());
        
        return Result.success("密码修改成功");
    }
} 