package com.universidad.seguridad.controller;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.security.UsuarioPrincipal;
import com.universidad.seguridad.service.TareaService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/tareas")
public class ApiTareaController {

    private final TareaService service;

    public ApiTareaController(TareaService service) {
        this.service = service;
    }

    // Lo que se devuelve en JSON: sin el objeto Usuario completo, para no
    // exponer el hash de la contraseña del propietario.
    public record TareaResponse(Long id, String titulo, String descripcion,
                                boolean completada, String propietario) {
        static TareaResponse de(Tarea t) {
            return new TareaResponse(t.getId(), t.getTitulo(), t.getDescripcion(),
                    t.isCompletada(), t.getPropietario().getEmail());
        }
    }

    @GetMapping
    public List<TareaResponse> misTareas(Authentication auth) {
        // Authentication llega poblado por JwtAuthFilter, exactamente como
        // llegaría si la petición viniera autenticada por sesión: el resto de
        // la aplicación no necesita saber cuál mecanismo se usó.
        UsuarioPrincipal usuario = (UsuarioPrincipal) auth.getPrincipal();
        return service.listarDe(usuario.getId()).stream()
                .map(TareaResponse::de)
                .toList();
    }
}
