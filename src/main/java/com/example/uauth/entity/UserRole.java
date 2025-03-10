package com.example.uauth.entity;

import java.io.Serializable;
import java.util.Date;

/**
 * 用户角色关联实体类
 */
public class UserRole implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private Long id;
    private Long userId;
    private Long roleId;
    private Date createTime;
    
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public Long getUserId() {
        return userId;
    }
    
    public void setUserId(Long userId) {
        this.userId = userId;
    }
    
    public Long getRoleId() {
        return roleId;
    }
    
    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }
    
    public Date getCreateTime() {
        return createTime;
    }
    
    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
} 