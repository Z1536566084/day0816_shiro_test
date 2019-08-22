package com.qf.pojo;

import lombok.Data;

import java.io.Serializable;
@Data
public class SysRole implements Serializable {
    private long role_id;       //角色id
    private String role_name;   //角色名称
    private String role_desc;   //角色描述
    private int if_vilid;       //是否有效
}
