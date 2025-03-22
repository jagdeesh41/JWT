package com.learn.security.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@EnableMethodSecurity
public class SecurityController {


    @GetMapping("/hello")
    @PreAuthorize("hasRole('USER')")
    public String greet()
    {
        return "hi from user";
    }
    @GetMapping("/hi")
    @PreAuthorize("hasRole('ADMIN')")
    public String greeting()
    {
        return "hi from admin";
    }

}
