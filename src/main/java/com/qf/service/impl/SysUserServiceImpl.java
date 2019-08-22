package com.qf.service.impl;


import com.qf.mapper.SysUserMapper;
import com.qf.pojo.SysPermission;
import com.qf.pojo.SysUser;
import com.qf.service.SysUserService;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class SysUserServiceImpl implements SysUserService {

    @Autowired
    private SysUserMapper userMapper;
    //根据登录名查询用户信息
    @Override
    public SysUser findUserByLoginName(String loginName) {
        SysUser sysUser = userMapper.findUserInfoByLoginName(loginName);
        return sysUser;
    }
    //根据登录名查询当前用户权限集合
    @Override
    public List<SysPermission> findPermissionsByLoginName(String loginName) {
        List<SysPermission> permissions = userMapper.findPermissionsByUserName(loginName);
        return permissions;
    }
    //向数据库添加新的用户信息
    @Override
    public boolean saveUser(SysUser sysUser) {
        ByteSource salt = ByteSource.Util.bytes("abc");
        String s = new SimpleHash("MD5", sysUser.getPassword(), salt, 1024).toString();
        int i = userMapper.saveUser(sysUser);
        return i>0?true:false;
    }

    @Override
    public int getMaxUserId() {
        return userMapper.getMaxUserId();
    }


    //获取所有的用户对象信息
    @Override
    public List<SysUser> loadAll() {
        List<SysUser> userList = userMapper.loadAll();
        return userList;
    }
    //根据用户id删除用户对象信息
    @Override
    public boolean delUserByUserId(int userId) {
        return userMapper.delUserByUserId(userId)>0?true:false;
    }


    //修改当前用户信息
    @Override
    public boolean updateByUser(SysUser sysUser) {
        int i = userMapper.updateByUser(sysUser);
        return i>0?true:false;
    }
    //根据当前用户id查询用户所有信息
    @Override
    public SysUser loadUserByUserId(int UserId) {
        SysUser sysUser = userMapper.loadUserByUserId(UserId);
        return sysUser;
    }


}
