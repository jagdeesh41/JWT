package com.learn.security.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
public class LoginRequest {
    @JsonProperty(value = "username")
    private String userName;
    private String password;
}
