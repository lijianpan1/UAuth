package com.example.uauth.security;

import com.example.uauth.entity.User;
import com.example.uauth.service.UserService;
import com.example.uauth.util.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * JWT用户详情服务
 */
@Service
public class JwtUserDetailsService implements UserDetailsService {

    @Autowired
    private UserService userService;
    
    @Override
    public JwtUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 获取用户信息
        Result<User> userResult = userService.getUserByUsername(username);
        if (userResult.getCode() != 200 || userResult.getData() == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        
        User user = userResult.getData();
        
        // 获取用户角色
        Result<List<String>> rolesResult = userService.getUserRoles(user.getId());
        List<String> roles = rolesResult.getData();
        
        // 获取用户权限
        Result<List<String>> permissionsResult = userService.getUserPermissions(user.getId());
        List<String> permissions = permissionsResult.getData();
        
        // 创建UserDetails对象
        return new JwtUserDetails(
                user.getId(),
                user.getUsername(),
                user.getPassword(),
                user.getRealName(),
                user.getStatus(),
                roles,
                permissions
        );
    }
} 