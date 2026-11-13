package com.universidad.seguridad.service;

import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.UsuarioRepository;
import com.universidad.seguridad.security.UsuarioPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UsuarioDetailsService implements UserDetailsService {

    private final UsuarioRepository repo;

    public UsuarioDetailsService(UsuarioRepository repo) {
        this.repo = repo;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario u = repo.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + email));

        // Se devuelve UsuarioPrincipal (y no User.builder()) para conservar el id:
        // el rol ya viene con el prefijo ROLE_ desde la base de datos.
        return new UsuarioPrincipal(
                u.getId(),
                u.getEmail(),
                u.getContrasenia(),          // BCrypt hash
                u.isActivo(),
                List.of(new SimpleGrantedAuthority(u.getRol())));
    }
}
