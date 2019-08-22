package com.qf.service;


import com.qf.pojo.SysPermission;
import com.qf.pojo.SysUser;

import java.util.List;

public interface SysUserService {
    /**
     *@Param注解的作用是给参数命名,参数命名后就能根据名字得到参数值,正确的将参数传入sql语句中（一般通过#{}的方式，${}会有sql注入的问题）。
     * @param loginName 登录名
     * @return  SysUser 用户对象信息
     * 根据登录名查询用户信息
     *
     */
    public SysUser findUserByLoginName(String loginName);

    /**
     * 根据用户名查询用户已经拥有的权限
     * @param loginName 登录名(用户名)
     * @return SysPermission对象的集合
     */
    public List<SysPermission> findPermissionsByLoginName(String loginName);

    /**
     * 向数据库添加新用户
     * @param sysUser
     * @return
     */
    public boolean saveUser(SysUser sysUser);

    /**
     * 获取用户最大id值
     * @return
     */
    public int getMaxUserId();

    /**
     * 获取所有的用户对象
     * @return 所有的用户对象集合
     */
    public List<SysUser> loadAll();

    /**
     * 根据用户id删除用户对象信息
     * @param userId
     * @return
     */
    public boolean delUserByUserId(int userId);

    /**
     * //修改当前用户信息
     * @param sysUser 当前用户
     * @return
     */
    public boolean updateByUser(SysUser sysUser);

    /**
     * 根据当前用户id查询其信息
     * @param UserId
     * @return 当前用户信息集合
     */
    public SysUser loadUserByUserId(int UserId);
}
