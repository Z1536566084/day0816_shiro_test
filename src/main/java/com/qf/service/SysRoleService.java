package com.qf.service;

import com.qf.pojo.SysRole;

import java.util.List;

public interface SysRoleService {
    /**
     * 获取所有角色信息
     * @return 所有角色集合
     */
    public List<SysRole> loadRoleAll();
}
