package com.learn.security.jwt;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

@Component
@Slf4j
public class JwtUtils {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiry}")
    private long expiryMs;


    public String getJwtFromHeader(HttpServletRequest httpServletRequest)
    {
        String bearerToken = httpServletRequest.getHeader("Authorization");
        log.info("bearer Token : {}",bearerToken);
        if(Objects.nonNull(bearerToken) && bearerToken.startsWith("Bearer "))
        {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String generateJwtTokenFromUserName(UserDetails userDetails)
    {
        String userName = userDetails.getUsername();
        long current = new Date().getTime();
        long expiry =  current + expiryMs;
        String jwtToken = Jwts.builder()
                .signWith(key())
                .issuedAt(new Date(current))
                .expiration(new Date(expiry))
                .subject(userName)
                .compact();
        log.info("JWT Token : {}",jwtToken);
        return  jwtToken;
    }

    public String getUserNameFromJwtToken(String token)
    {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();

    }

    public boolean validateJwtToken(String jwtToken)
    {
        try
        {
            log.info("Validating jwt token");
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(jwtToken);
            return true;
        }
        catch (MalformedJwtException e)
        {
            log.error("Invalid JWT token{}",e.getMessage());
        }
        catch (ExpiredJwtException e)
        {
            log.error("JWT token is expired : {}",e.getMessage());
        }
        catch (UnsupportedJwtException e)
        {
            log.error("JWT token is unsupported : {}", e.getMessage());
        }
        catch (Exception e)
        {
            log.error("Exception while validating JWT Token");
        }
        return false;
    }

    private Key key()
    {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));

    }
}
