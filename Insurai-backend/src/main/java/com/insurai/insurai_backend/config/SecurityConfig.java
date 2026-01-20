package com.insurai.insurai_backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfig {

    private final EmployeeJwtAuthenticationFilter employeeJwtAuthenticationFilter;
    private final AgentJwtAuthenticationFilter agentJwtAuthenticationFilter;
    private final HrJwtAuthenticationFilter hrJwtAuthenticationFilter;

    public SecurityConfig(EmployeeJwtAuthenticationFilter employeeJwtAuthenticationFilter,
                          AgentJwtAuthenticationFilter agentJwtAuthenticationFilter,
                          HrJwtAuthenticationFilter hrJwtAuthenticationFilter) {
        this.employeeJwtAuthenticationFilter = employeeJwtAuthenticationFilter;
        this.agentJwtAuthenticationFilter = agentJwtAuthenticationFilter;
        this.hrJwtAuthenticationFilter = hrJwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers("/", "/health", "/actuator/**", "/error").permitAll()
                
                // Public authentication endpoints
                .requestMatchers(
                    "/auth/**",
                    "/auth/forgot-password",
                    "/auth/reset-password/**", 
                    "/employee/login",
                    "/agent/login",
                    "/employee/register",
                    "/hr/login"
                ).permitAll()
                
                // Public resources
                .requestMatchers("/uploads/**").permitAll()
                .requestMatchers("/employee/policies").permitAll()
                
                // Public admin endpoints
                .requestMatchers("/admin/**").permitAll()
                .requestMatchers("/admin/policies").permitAll()
                .requestMatchers("/admin/policies/save").permitAll()
                
                // Public agent endpoints
                .requestMatchers("/agent/availability/**").permitAll()
                .requestMatchers("/agent/queries/pending/**").permitAll()
                
                // Temporarily public
                .requestMatchers("/employees/**").permitAll()
                .requestMatchers("/hr/**").permitAll()
                
                // Secured Employee endpoints
                .requestMatchers("/employee/claims/**").hasRole("EMPLOYEE")
                .requestMatchers("/employee/queries/**").hasRole("EMPLOYEE")
                .requestMatchers("/employee/chatbot").hasRole("EMPLOYEE")
                .requestMatchers("/employee/**").hasRole("EMPLOYEE")
                
                // Secured Agent endpoints
                .requestMatchers("/agent/queries/respond/**").hasRole("AGENT")
                .requestMatchers("/agent/queries/all/**").hasRole("AGENT")
                .requestMatchers("/agent/**").hasRole("AGENT")
                
                // Secured HR/Admin endpoints
                .requestMatchers("/hr/claims").hasAnyRole("HR", "ADMIN")
                .requestMatchers("/admin/claims").hasAnyRole("HR", "ADMIN")
                .requestMatchers("/hr/claims/fraud").hasRole("HR")
                .requestMatchers("/admin/claims/fraud").hasRole("ADMIN")
                .requestMatchers(
                    "/claims/approve/**",
                    "/claims/reject/**",
                    "/claims/all"
                ).hasAnyRole("HR", "ADMIN")
                
                // Notifications endpoints
                .requestMatchers("/notifications/user/**").hasAnyAuthority("ROLE_EMPLOYEE", "ROLE_HR", "ROLE_ADMIN")
                .requestMatchers("/notifications/**").hasAnyRole("HR", "ADMIN")
                .requestMatchers("/notifications/*/read").hasAnyAuthority("ROLE_EMPLOYEE", "ROLE_HR", "ROLE_ADMIN")

                .anyRequest().authenticated()
            )
            .httpBasic(httpBasic -> httpBasic.disable())
            .formLogin(formLogin -> formLogin.disable());

        http.addFilterBefore(employeeJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(agentJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(hrJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // ⚠️ IMPORTANT: Add your actual Netlify URL here
        configuration.setAllowedOrigins(Arrays.asList(
            "https://insureai3.netlify.app/",  // ← CHANGE THIS
            "http://localhost:5173",
            "http://localhost:3000",
            "http://localhost:5174"
        ));
        
        configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
        ));
        
        configuration.setAllowedHeaders(Arrays.asList("*"));
        
        configuration.setExposedHeaders(Arrays.asList(
            "Authorization", 
            "Content-Type"
        ));
        
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}