package com.universidad.seguridad.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * Usuario autenticado que además conserva el id de la base de datos.
 * Sin este id, la regla "#usuarioId == authentication.principal.id" de
 * TareaService no se puede evaluar, porque el User de Spring Security
 * solo guarda username, password y roles.
 */
public class UsuarioPrincipal extends User {

    private final Long id;

    public UsuarioPrincipal(Long id, String email, String contrasenia, boolean activo,
                            Collection<? extends GrantedAuthority> roles) {
        super(email, contrasenia, activo, true, true, true, roles);
        this.id = id;
    }

    public Long getId() { return id; }
}
