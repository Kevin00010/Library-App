package com.mongo.libapp.security.services;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.mongo.libapp.config.Constants;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    // retrieve username from jwt token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // extract claims from jwt token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // generate token for user
    public String generateToken(Authentication authentication) {
        return generateToken(new HashMap<>(), authentication);
    }

    /*
     * while creating the token -
     * 1. Define claims of the token, like Issuer, Expiration, Subject, and the ID
     * 2. Sign the JWT using the HS512 algorithm and secret key.
     * 3. According to JWS Compact
     * Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-
     * 41#section-3.1)
     * compaction of the JWT to a URL-safe string
     */
    public String generateToken(
            Map<String, Object> extraClaims,
            Authentication authentication) {

        UserDetailsImp userPrincipal = (UserDetailsImp) authentication.getPrincipal();

        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + Constants.EXPIRATION_TIME))
                .signWith(getSignIngKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // validate token
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    // extract all claims from jwt token
    private Claims extractAllClaims(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(getSignIngKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        System.out.println("claims :  " + claims);
        return claims;
    }

    // check if the token has expired
    private boolean isTokenExpired(String token) {
        final Date expiration = extractExpiration(token);
        return expiration.before(new Date());
    }

    // retrieve expiration date from jwt token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Key getSignIngKey() {
        byte[] keyBytes = Decoders.BASE64.decode(Constants.SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}