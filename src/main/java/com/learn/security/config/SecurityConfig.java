package com.learn.security.config;

import com.learn.security.jwt.AuthJwtTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

//    @Autowired
//    private DataSource dataSource;

    @Autowired
    private AuthenticationEntryPoint unauthorizedHandler;

    @Bean
    public AuthJwtTokenFilter authenticationJwtTokenFilter()
    {
        return  new AuthJwtTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }


    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/signin").permitAll()
                .anyRequest().authenticated());
//        http.httpBasic(withDefaults());
        http.exceptionHandling(exception->exception.authenticationEntryPoint(unauthorizedHandler));
        http.csrf(csrf->csrf.disable());
        http.headers(headers-> headers.
                frameOptions(frameOptionsConfig ->
                        frameOptionsConfig.sameOrigin()));
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource)
    {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userCreatedUserDetaisService, PasswordEncoder passwordEncoder)
    {
        return args->
        {
            JdbcUserDetailsManager userDetailsManager = (JdbcUserDetailsManager) userCreatedUserDetaisService;
            UserDetails userDetails = User.builder()
                    .username("user2")
                    .password(passwordEncoder.encode("password2"))
                    .roles("USER")
                    .build();
            UserDetails adminDetails = User.builder()
                    .username("admin2")
                    .password(passwordEncoder().encode("password2"))
                    .roles("ADMIN")
                    .build();
            userDetailsManager.createUser(userDetails);
            userDetailsManager.createUser(adminDetails);

        };



    }

    @Bean
    PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }


}
