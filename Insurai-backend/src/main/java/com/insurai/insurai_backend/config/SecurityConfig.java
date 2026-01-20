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
            .cors(cors -> {}) // Keep global CORS
            .authorizeHttpRequests(auth -> auth
                // ✅✅✅ MOST IMPORTANT: Public endpoints FIRST ✅✅✅
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
                
                // Public admin endpoints (you can secure later)
                .requestMatchers("/admin/**").permitAll()
                .requestMatchers("/admin/policies").permitAll()
                .requestMatchers("/admin/policies/save").permitAll()
                
                // Public agent endpoints
                .requestMatchers("/agent/availability/**").permitAll()
                .requestMatchers("/agent/queries/pending/**").permitAll()
                
                // Temporarily public (you can secure later)
                .requestMatchers("/employees/**").permitAll()
                .requestMatchers("/hr/**").permitAll()
                
                // 🔒 Secured Employee endpoints
                .requestMatchers("/employee/claims/**").hasRole("EMPLOYEE")
                .requestMatchers("/employee/queries/**").hasRole("EMPLOYEE")
                .requestMatchers("/employee/chatbot").hasRole("EMPLOYEE")
                .requestMatchers("/employee/**").hasRole("EMPLOYEE")
                
                // 🔒 Secured Agent endpoints
                .requestMatchers("/agent/queries/respond/**").hasRole("AGENT")
                .requestMatchers("/agent/queries/all/**").hasRole("AGENT")
                .requestMatchers("/agent/**").hasRole("AGENT")
                
                // 🔒 Secured HR/Admin claim endpoints
                .requestMatchers("/hr/claims").hasAnyRole("HR", "ADMIN")
                .requestMatchers("/admin/claims").hasAnyRole("HR", "ADMIN")
                .requestMatchers("/hr/claims/fraud").hasRole("HR")
                .requestMatchers("/admin/claims/fraud").hasRole("ADMIN")
                .requestMatchers(
                    "/claims/approve/**",
                    "/claims/reject/**",
                    "/claims/all"
                ).hasAnyRole("HR", "ADMIN")
                
                // 🔒 Notifications endpoints
                .requestMatchers("/notifications/user/**").hasAnyAuthority("ROLE_EMPLOYEE", "ROLE_HR", "ROLE_ADMIN")
                .requestMatchers("/notifications/**").hasAnyRole("HR", "ADMIN")
                .requestMatchers("/notifications/*/read").hasAnyAuthority("ROLE_EMPLOYEE", "ROLE_HR", "ROLE_ADMIN")

                // Everything else requires authentication
                .anyRequest().authenticated()
            )
            .httpBasic(httpBasic -> httpBasic.disable())
            .formLogin(formLogin -> formLogin.disable());

        // Add JWT filters in order
        http.addFilterBefore(employeeJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(agentJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(hrJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
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