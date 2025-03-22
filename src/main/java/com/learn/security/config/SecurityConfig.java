package com.learn.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/h2-console/**")
                .permitAll()
                .anyRequest()
                .authenticated());
        http.httpBasic(withDefaults());
        http.csrf(csrf->csrf.disable());
        http.headers(headers->
                headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin()));
        return http.build();
    }

    @Primary
    @Bean
    UserDetailsService inDb()
    {
        UserDetails userDetails = User.builder()
                .username("user2")
                .password("{noop}password2")
                .roles("USER")
                .build();
        UserDetails adminDetails = User.builder()
                .username("admin2")
                .password("{noop}password2")
                .roles("ADMIN")
                .build();
        UserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(userDetails);
        userDetailsManager.createUser(adminDetails);
        return userDetailsManager;
    }


}
