package com.onemed1a.backend.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;

/* Utility class for generating and validating JWT tokens. */
@Component
public class JwtTokenProvider {

    private final Key key;
    private final long expirationTime;

    /**
     * Constructs a JwtTokenProvider with the specified secret and expiration time.
     * 
     * @param secret the secret key for signing the JWT
     * @param expirationTime the expiration time in milliseconds
     */
    public JwtTokenProvider(@Value("${jwt.secret}") String secret,
                            @Value("${jwt.expiration}") long expirationTime) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationTime = expirationTime;
    }

    /**
     * Generates a JWT token for the given user ID.
     * 
     * @param userId the user ID
     * @return the generated JWT token
     */
    public String generateToken(UUID userId) {
        return Jwts.builder()
                .setSubject(userId.toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Validates the JWT token and returns the user ID if valid.
     * 
     * @param token the JWT token
     * @return the user ID if the token is valid
     */
    public UUID validateTokenAndGetUserId(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return UUID.fromString(claims.getSubject());
        } catch (JwtException | IllegalArgumentException e) {
            throw new RuntimeException("Invalid or expired JWT token");
        }
    }
}
