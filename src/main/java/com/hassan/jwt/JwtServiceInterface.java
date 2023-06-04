package com.hassan.jwt;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;
import java.util.function.Function;

public interface JwtServiceInterface {

    /**
     * Extracts the username from the token.
     * @param token The JWT token.
     * @return The extracted username.
     */
    String extractUsername(String token);

    /**
     * Extracts a claim from the token using the provided claims resolver function.
     * @param token The JWT token.
     * @param claimsResolver The claims resolver function to extract a specific claim.
     * @param <T>   The type of the claim.
     * @return The extracted claim.
     */
    <T> T extractClaim(String token, Function<Claims, T> claimsResolver);

    /**
     * Generates a JWT token with the provided claims and user details.
     * @param claims The claims to include in the token.
     * @param userDetails The user details associated with the token.
     * @return The generated JWT token.
     */
    String generateToken(Map<String, Object> claims, UserDetails userDetails);

    /**
     * Generates a JWT token with the provided user details.
     * @param userDetails The user details associated with the token.
     * @return The generated JWT token.
     */
    String generateToken(UserDetails userDetails);

    /**
     * Validates the JWT token for the given user details.
     * @param token  The JWT token to validate.
     * @param userDetails The user details associated with the token.
     * @return {@code true} if the token is valid for the user details, {@code false} otherwise.
     */
    public boolean isTokenValidOrExpired(String token , UserDetails userDetails);

    /**
     * Checks if the JWT token has expired.
     * @param token The JWT token.
     * @return {@code true} if the token has expired, {@code false} otherwise.
     */
    boolean isTokenExpired(String token);
}
