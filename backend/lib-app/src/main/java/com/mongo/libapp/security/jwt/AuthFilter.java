package com.mongo.libapp.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mongo.libapp.config.Constants;
import com.mongo.libapp.security.services.JwtService;
import com.mongo.libapp.security.services.UserDetailsServiceImp;

import io.jsonwebtoken.ExpiredJwtException;

public class AuthFilter extends OncePerRequestFilter {
    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserDetailsServiceImp userDetailsService;

    @Autowired
    protected void doFilterInternal(
            @NonNull HttpServletRequest request, // Servlet request object that will be used to filter the returned
                                                 // results when the filter is applied to the request object
            @NonNull HttpServletResponse response, // Servlet response object that will be used to filter the returned
                                                   // results when the filter is applied to the response object
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader(Constants.HEADER_STRING); // get the authorization header
        String jwt = null;
        String username = null;

        // check if the authentication header is present in the request or if it starts
        // with "Bearer " (for Bearer authentication)
        if (StringUtils.hasText(authHeader)) {
            if (authHeader.startsWith(Constants.TOKEN_PREFIX)) {
                jwt = authHeader.substring(Constants.BEGIN_INDEX);
                try {
                    username = jwtService.extractUsername(jwt);
                } catch (IllegalArgumentException e) {
                    System.out.println("Unable to extract JWT token");
                } catch (ExpiredJwtException e) {
                    System.out.println("JWT token expired");
                }
            } else {
                logger.warn("JWT token does not begin with Bearer String");
            }
        }
        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            // if token is valid configure Spring Security to manually set
            // authentication
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));
                // After setting the Authentication in the context, we specify
                // that the current user is authenticated. So it passes the
                // Spring Security Configurations successfully.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }

}
