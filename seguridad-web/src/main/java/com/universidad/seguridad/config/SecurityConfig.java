package com.universidad.seguridad.config;

import com.universidad.seguridad.security.JwtAuthFilter;
import com.universidad.seguridad.service.UsuarioDetailsService;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public DaoAuthenticationProvider authProvider(UsuarioDetailsService uds, PasswordEncoder pe) {
        DaoAuthenticationProvider p = new DaoAuthenticationProvider();
        p.setUserDetailsService(uds);
        p.setPasswordEncoder(pe);
        return p;
    }

    // AuthenticationManager expuesto como bean para que ApiAuthController
    // valide credenciales con el mismo UserDetailsService y BCrypt de la Parte 1
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // JwtAuthFilter es un @Component: sin esto, Spring Boot también lo
    // registraría como filtro global del servidor y se ejecutaría en TODAS las
    // peticiones (incluidas las vistas con sesión). Así solo corre dentro de
    // apiFilterChain, donde se agrega explícitamente.
    @Bean
    public FilterRegistrationBean<JwtAuthFilter> jwtAuthFilterRegistro(JwtAuthFilter filtro) {
        FilterRegistrationBean<JwtAuthFilter> registro = new FilterRegistrationBean<>(filtro);
        registro.setEnabled(false);
        return registro;
    }

    // Cadena de filtros para la API REST — stateless con JWT.
    // @Order(1): se evalúa ANTES que webFilterChain (@Order(2)): más
    // específico primero.
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
        http
            .securityMatcher("/api/**") // esta cadena SOLO aplica a /api/**
            .csrf(csrf -> csrf.disable()) // correcto aquí: no hay cookie de sesión
                                          // que un atacante pueda aprovechar; el token
                                          // va en un header que un formulario
                                          // cross-site no puede fijar por sí solo
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // Sin token (o con token inválido) la API responde 401 en vez de
            // redirigir a /login como haría la cadena de sesión
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // Cadena de filtros para las vistas web con Thymeleaf — basada en sesión.
    // @Order(2): se evalúa después de la cadena de /api/**, que tiene @Order(1)
    // y mayor prioridad. Sin @Order explícito, Spring Security no garantiza cuál
    // cadena evalúa primero cuando hay más de un SecurityFilterChain.
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/**") // todo lo que no sea /api/**
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/registro",
                                 "/css/**", "/js/**", "/error").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            );
            // CSRF queda ACTIVO (comportamiento por defecto de Spring Security):
            // esta cadena sirve formularios Thymeleaf con cookie de sesión,
            // el escenario exacto que CSRF protege.
        return http.build();
    }
}
