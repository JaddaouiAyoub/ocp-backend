package org.jad.auth.config;


import lombok.RequiredArgsConstructor;

import org.jad.auth.enums.Role;
import org.jad.auth.handler.CustomAccessDeniedHandler;
import org.jad.auth.handler.CustomAuthenticationEntryPoint;
import org.jad.auth.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity // ✅ Cette ligne est cruciale pour que @PreAuthorize fonctionne !

public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserService userService;
    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;

    //Configure les filtres de sécurité et les règles d'autorisation.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**","/api/v1/auth/**").permitAll()
                        .requestMatchers("/api/v1/auth/**")
                        .permitAll()
//                        .requestMatchers("/api/v1/collaborateurs/**").hasAnyAuthority(RoleCollaborateur.CHEF_EQUIPE.name(), RoleCollaborateur.COLLABORATEUR.name())
//                        .requestMatchers("/api/v1/conges/**").hasAnyAuthority(RoleCollaborateur.CHEF_EQUIPE.name(), RoleCollaborateur.COLLABORATEUR.name())
//                        .requestMatchers("/api/v1/equipes/**").hasAnyAuthority(RoleCollaborateur.CHEF_EQUIPE.name(), RoleCollaborateur.COLLABORATEUR.name())
//                        .requestMatchers("/api/v1/niveaux/**").hasAnyAuthority(RoleCollaborateur.CHEF_EQUIPE.name(), RoleCollaborateur.COLLABORATEUR.name())
//                        .requestMatchers("/api/v1/exercices/**").hasAnyAuthority(RoleCollaborateur.CHEF_EQUIPE.name(), RoleCollaborateur.COLLABORATEUR.name())
//                        .requestMatchers("/api/v1/jours-feries/**").hasAnyAuthority(RoleCollaborateur.CHEF_EQUIPE.name(), RoleCollaborateur.COLLABORATEUR.name())
//                        .requestMatchers("/api/v1/solde-conge/**").hasAnyAuthority(RoleCollaborateur.CHEF_EQUIPE.name(), RoleCollaborateur.COLLABORATEUR.name())
                        .requestMatchers("/api/test/admin").hasAuthority( Role.ADMIN.name())
                         .anyRequest().authenticated())
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(exception ->
                        exception.accessDeniedHandler(customAccessDeniedHandler)
                                .authenticationEntryPoint(customAuthenticationEntryPoint)
                                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(
                        jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class
                );
        return http.build();
    }
    //Définit le fournisseur d'authentification pour vérifier les utilisateurs.
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authenticationProvider= new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userService.userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    //Gère l'authentification des utilisateurs.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception{
        return config.getAuthenticationManager();
    }
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowCredentials(true);
        configuration.addAllowedOrigin("http://localhost:4200");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}