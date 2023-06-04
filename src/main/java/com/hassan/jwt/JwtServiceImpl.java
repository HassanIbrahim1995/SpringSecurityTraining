package com.hassan.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public final class JwtServiceImpl implements JwtServiceInterface{

    @Override
    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }

    @Override
    public <T> T extractClaim(String token , Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    @Override
    public boolean isTokenExpired(String token) {
        final Date expirationDate = extractClaim(token, Claims::getExpiration);
        return expirationDate != null && expirationDate.before(new Date());
    }

    @Override
    public boolean isTokenValidOrExpired(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        boolean isTokenValid = username.equals(userDetails.getUsername());
        boolean isTokenExpired = isTokenExpired(token);
        return isTokenValid && !isTokenExpired;
    }

    @Override
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    @Override
    public String generateToken(Map<String,Object> claims , UserDetails userDetails){
        return Jwts.builder().setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.ES256)
                .compact();
    }

    /**
     * Extracts all claims from the token.
     * @param token The JWT token.
     * @return The extracted claims.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJwt(token)
                .getBody();
    }

    /**
     * Retrieves the signing key used to verify the token signature.
     * @return The signing key.
     */
    private Key getSignInKey() {
        final String SECRET_KEY = "7A24432646294A404E635266556A586E327234753778214125442A472D4B6150";
        byte[] keyBytes = Base64.getDecoder().decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
