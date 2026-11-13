package com.universidad.seguridad.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);

            if (jwtUtil.esValido(token)) {
                var roles = List.of(new SimpleGrantedAuthority(jwtUtil.extraerRol(token)));
                // El principal se arma con los datos del propio token (id, email, rol):
                // no se consulta la base de datos en cada petición.
                var principal = new UsuarioPrincipal(jwtUtil.extraerId(token),
                        jwtUtil.extraerEmail(token), "", true, roles);

                var authToken = new UsernamePasswordAuthenticationToken(principal, null, roles);
                // Puebla el SecurityContext manualmente: no hay sesión de la que
                // Spring Security pueda recuperar el usuario en la siguiente petición,
                // así que este filtro se ejecuta en CADA petición a /api/**.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            // Si el token no es válido, simplemente no se autentica: la
            // SecurityFilterChain decide si la ruta requería autenticación y
            // responde 401 en ese caso.
        }

        chain.doFilter(request, response);
    }
}
