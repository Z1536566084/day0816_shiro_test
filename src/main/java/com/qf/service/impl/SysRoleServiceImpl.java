package com.qf.service.impl;

import com.qf.mapper.SysRoleMapper;
import com.qf.pojo.SysRole;
import com.qf.service.SysRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SysRoleServiceImpl implements SysRoleService {
    @Autowired
    private SysRoleMapper roleMapper;
    //获取所有角色信息
    @Override
    public List<SysRole> loadRoleAll() {
        List<SysRole> roleList = roleMapper.loadRoleAll();
        return roleList;
    }
}
