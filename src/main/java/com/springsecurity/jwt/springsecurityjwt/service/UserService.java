package com.springsecurity.jwt.springsecurityjwt.service;

import com.springsecurity.jwt.springsecurityjwt.model.Role;
import com.springsecurity.jwt.springsecurityjwt.model.User;

import java.util.List;

public interface UserService {

    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
}
