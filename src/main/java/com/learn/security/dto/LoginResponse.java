package com.learn.security.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class LoginResponse {
    private String jwtToken;
    private String userName;
    private List<String> roles;
}
