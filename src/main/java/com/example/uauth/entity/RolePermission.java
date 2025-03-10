package com.example.uauth.entity;

import java.io.Serializable;
import java.util.Date;

/**
 * 角色权限关联实体类
 */
public class RolePermission implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private Long id;
    private Long roleId;
    private Long permissionId;
    private Date createTime;
    
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    public Long getRoleId() {
        return roleId;
    }
    
    public void setRoleId(Long roleId) {
        this.roleId = roleId;
    }
    
    public Long getPermissionId() {
        return permissionId;
    }
    
    public void setPermissionId(Long permissionId) {
        this.permissionId = permissionId;
    }
    
    public Date getCreateTime() {
        return createTime;
    }
    
    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }
} 