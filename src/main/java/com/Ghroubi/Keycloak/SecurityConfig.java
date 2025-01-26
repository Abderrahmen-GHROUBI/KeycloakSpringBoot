package com.Ghroubi.Keycloak;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity

public class SecurityConfig {


    @Bean
    public JwtAuthConverter jwtAuthConverter() {
        return new JwtAuthConverter();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthConverter jwtAuthConverter = jwtAuthConverter();
        http
                .csrf()
                      .disable()
                .authorizeHttpRequests()
                      .anyRequest()
                .authenticated();
        http
                .oauth2ResourceServer()
                        .jwt()
                             .jwtAuthenticationConverter(jwtAuthConverter);
        http
                .sessionManagement()
                .sessionCreationPolicy(STATELESS);
        return http.build();


    }
}
