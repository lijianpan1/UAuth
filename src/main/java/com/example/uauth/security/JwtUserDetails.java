package com.example.uauth.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT用户详情类
 */
public class JwtUserDetails implements UserDetails {

    private Long id;
    private String username;
    private String password;
    private String realName;
    private Integer status;
    private List<String> roles;
    private List<String> permissions;
    
    public JwtUserDetails(Long id, String username, String password, String realName, Integer status, List<String> roles, List<String> permissions) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.realName = realName;
        this.status = status;
        this.roles = roles;
        this.permissions = permissions;
    }
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 将角色和权限转换为GrantedAuthority
        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        
        authorities.addAll(permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList()));
        
        return authorities;
    }
    
    @Override
    public String getPassword() {
        return password;
    }
    
    @Override
    public String getUsername() {
        return username;
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    public boolean isEnabled() {
        return status == 1;
    }
    
    public Long getId() {
        return id;
    }
    
    public String getRealName() {
        return realName;
    }
    
    public List<String> getRoles() {
        return roles;
    }
    
    public List<String> getPermissions() {
        return permissions;
    }
} 