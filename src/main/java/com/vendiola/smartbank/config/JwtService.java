package com.vendiola.smartbank.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "YgbFKWZsRd84AA9RfcmjRk52wZB7fTnPqVrFP6ew7geFMXn4egbYkkDS5UtWAjjp7QjGfahK9mG8SYL8gfU5cUX2EVxTacrputtYjxtHkGFUcaMG4r8mafJ8WP7s5T9sV5LksQMJm6rguFnDtsUt2fUxg7czdKNQAsgskguyGugp6yENcDZVAW6jctNRHpAF8M3CqfqtG2mR3WZTEjVXBzrvTh3ynnT9QAJA9wx4YxKSCHx6fsa8XuwA8vhAyVmmSqgRnUXhqzJxb3mJcqhfxA6R7YsntScZFpWrnRWkTubpMTh8cybEsZTfsHGDjM2kU9tUArTN2s2YQGWydydFq2hKaUKDhuduZPnAUZ7q3e2CK44zRhPPh4eyK6nepFZMpbkXJKbHay6xGYbQgan8sYKqEgmCmjjCYSRcVGtHaYyFDwVwvpAvGKurAtqxJGRX2L7mVWLrjhzPRNDm4gM8J5QZd5qR2r2NxH6dptchazCkMuUxXnrn4shwaWrV2Jsd";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, @NotNull Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private @NotNull Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, @NotNull UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (1000 * 60 * 60 * 24)))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
