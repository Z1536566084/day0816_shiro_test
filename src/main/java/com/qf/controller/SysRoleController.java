package com.qf.controller;

import com.qf.pojo.SysRole;
import com.qf.service.SysRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
public class SysRoleController {
    @Autowired
    private SysRoleService roleService;
    //获取所有角色信息
    @RequestMapping("/loadRoleAll")
    public String loadRoleAll(Model model){
        List<SysRole> roleList = roleService.loadRoleAll();
        model.addAttribute("roleList",roleList);
        return "role";
    }

}
