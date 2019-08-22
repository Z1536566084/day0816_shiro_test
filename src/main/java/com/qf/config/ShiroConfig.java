package com.qf.config;

import com.qf.shiro.MyRealm;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration //告诉系统本事是一个配置类(用此对象初始化系统)
public class ShiroConfig {
//创建shiro安全过滤器

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(
            @Qualifier("defaultWebSecurityManager")DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
        //给过滤器装配安全策略
        filterFactoryBean.setSecurityManager(defaultWebSecurityManager);
        Map<String,String> map=new HashMap<>();
        //定义过滤规则
        map.put("/main","authc");//需要登录后才能访问的资源
        map.put("/borrow","authc");
        //map.put("/one","perms[user_edit]");//需要登录后，且拥有user/edit权限的账户才可访问
        //map.put("/two","perms[user_forbidden]");//需要登录后，且拥有user/edit权限的账户才可访问

        //被aop注解代替
        filterFactoryBean.setFilterChainDefinitionMap(map);//需要过滤链的定义
        filterFactoryBean.setLoginUrl("/indexView");//设置默认登陆的页面
        filterFactoryBean.setUnauthorizedUrl("/unoauth");//权限不足时访问的页面
        return filterFactoryBean;
    }

    @Bean("defaultWebSecurityManager")
    public DefaultWebSecurityManager defaultWebSecurityManager(@Qualifier("myRealm")MyRealm myRealm){
        DefaultWebSecurityManager webSecurityManager = new DefaultWebSecurityManager();
        //组装realm到securityManager中
        webSecurityManager.setRealm(myRealm);
        return webSecurityManager;
    }

    @Bean("myRealm")
    public MyRealm myRealm(
            @Qualifier("hashedCredentialsMatcher")HashedCredentialsMatcher hashedCredentialsMatcher){
        MyRealm myRealm = new MyRealm();
        //装配凭证匹配器到myRealm中
        myRealm.setCredentialsMatcher(hashedCredentialsMatcher);
        myRealm.setAuthorizationCachingEnabled(false);
        return myRealm;
    }
    //通过aop代理拦截权限设定
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    //设置注解拦截源码中的权限设定
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(
            @Qualifier("defaultWebSecurityManager") DefaultWebSecurityManager webSecurityManager
    ){
        AuthorizationAttributeSourceAdvisor sourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        sourceAdvisor.setSecurityManager(webSecurityManager);
        return sourceAdvisor;
    }

    //创建凭证匹配器
    @Bean(name = "hashedCredentialsMatcher")
    public HashedCredentialsMatcher hashedCredentialsMatcher(){
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        //设置加密算法
        credentialsMatcher.setHashAlgorithmName("MD5");
        //设置shiro缓存的凭证字符串编码
        credentialsMatcher.setStoredCredentialsHexEncoded(true);
        //设置hash频次
        credentialsMatcher.setHashIterations(1024);
        return credentialsMatcher;
    }

}
