package com.qf.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ViewController {
    //首页映射
    @RequestMapping("/indexView")
    public String indexView(){
        return "index";
    }
    //注册页面映射
    @RequestMapping("/regView")
        public String regView(){
        return "reg";
    }
}
