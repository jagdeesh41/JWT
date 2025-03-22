package com.learn.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Component
@Slf4j
public class AuthTokenFilter extends OncePerRequestFilter
{
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException
    {
        log.info("Request Interceptor Invoked.. ");

        try {
            log.info("Token Filter invoked");
            String jwt = jwtUtils.getJwtFromHeader(request);

            if (Objects.nonNull(jwt) && jwtUtils.validateJwtToken(jwt)) {
                String userName = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(userName);

                //Creation of Authentication Token
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                log.info("Roles from JWT : {}", userDetails.getAuthorities());
                // enhancing the token with additional details
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);


            }
        }
        catch (Exception e)
        {
            log.error("Cannot set user authentication : {}",e.getMessage());


        }
        filterChain.doFilter(request,response);

    }
}
