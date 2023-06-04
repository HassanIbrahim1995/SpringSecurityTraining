package com.hassan.config;

import com.hassan.jwt.JwtServiceInterface;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtServiceInterface jwtServiceImpl;
    private final UserDetailsService userDetailsService;


    /**
     * final String authHeader -> created why?
     * retrieving the value of the "Authorization"
     * header using request.getHeader("Authorization"), you can access the authentication information sent by the client
     * such as access tokens, bearer tokens, or other authentication-related data.
     * The retrieved value can then be used for authentication and authorization purposes
     */

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        //here check if the auth-header starts with bearer because the auth token starts with this Bearer
        if (authHeader == null || !authHeader.startsWith("Bearer")){
            // do not content and let spring handle the rest of the filters in the chain
            filterChain.doFilter(request,response);
            return;
        }

        //extract the token from the header
        jwt = authHeader.substring(7);
        userEmail = jwtServiceImpl.extractUsername(jwt);
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            //use the user service implemented in spring security to load the user from the database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtServiceImpl.isTokenValidOrExpired(jwt,userDetails)){
                // this needed by spring to update teh security context
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource()
                        .buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
       //now call the chain filter to pass the hand to the next filter
       filterChain.doFilter(request,response);
    }
}
