package org.jad.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jad.auth.User;
import org.jad.auth.service.JWTService;
import org.jad.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JWTService jwtService;
    private final UserService userService;
    @Autowired
    public JwtAuthenticationFilter(JWTService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }

    //Vérifie l'en-tête Authorization, extrait le JWT et valide l'utilisateur associé.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Ignore Swagger URLs pour éviter HTTP 401
        String requestURI = request.getRequestURI();
        if (requestURI.contains("/swagger-ui.html") || requestURI.contains("/swagger-ui/") || requestURI.contains("/v3/api-docs/")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader= request.getHeader("Authorization");
        final String jwt;
        final String username;
        // Vérifie si l'en-tête Authorization est présent et commence par "Bearer "
//        System.out.println("Authorization header: " + authHeader);
        if (StringUtils.isEmpty(authHeader) || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        // Extrait le JWT de l'en-tête Authorization
        jwt=authHeader.substring(7);
        username=jwtService.extractUsername(jwt);
        // Si le JWT est valide et qu'il n'y a pas d'authentification en cours, charge les détails de l'utilisateur
        if (!StringUtils.isEmpty(username) && SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails userDetails = userService.userDetailsService().loadUserByUsername(username);

            if (jwtService.isTokenValid(jwt, userDetails)){
                SecurityContext securityContext= SecurityContextHolder.createEmptyContext();
                // ✅ Affiche les autorités de l'utilisateur pour debug
//                System.out.println("Authorities for user " + username + ":");
//                userDetails.getAuthorities().forEach(auth -> System.out.println(" - " + auth.getAuthority()));
                UsernamePasswordAuthenticationToken token=new UsernamePasswordAuthenticationToken(
                        userDetails,null, userDetails.getAuthorities()
                );
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);
            }

            // Vérifie et traite le requesterId
            final String requesterId = request.getHeader("requesterId");
//            System.out.println("requesterId: " + requesterId);
            // Si le requesterId est vide, invalide ou ne correspond pas à l'email de l'utilisateur, envoie un statut 401
//            if (StringUtils.isEmpty(requesterId) || !requesterId.equalsIgnoreCase(userDetails.getUsername()) && !requesterId.equalsIgnoreCase(((User) userDetails).getUsername()) || !requesterId.equalsIgnoreCase(username)) {
//
//                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid requesterId");
//                return;
//            }
        }
//        System.out.println("Continuing with filter chain...");
        filterChain.doFilter(request,response);
    }


    private boolean isValidEmail(String email) {
        return userService.isValidEmail(email);
    }
}
