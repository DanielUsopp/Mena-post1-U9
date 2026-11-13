package com.universidad.seguridad.controller;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.security.UsuarioPrincipal;
import com.universidad.seguridad.service.TareaService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/tareas")
public class TareaController {

    private final TareaService service;

    public TareaController(TareaService service) {
        this.service = service;
    }

    @GetMapping
    public String misTareas(@AuthenticationPrincipal UsuarioPrincipal usuario, Model model) {
        model.addAttribute("tareas", service.listarDe(usuario.getId()));
        model.addAttribute("tarea", new Tarea());
        return "tareas/lista";
    }

    @PostMapping
    public String crear(@Valid @ModelAttribute Tarea tarea, BindingResult result,
                        @AuthenticationPrincipal UsuarioPrincipal usuario, Model model) {
        if (result.hasErrors()) {
            model.addAttribute("tareas", service.listarDe(usuario.getId()));
            return "tareas/lista";
        }
        service.crear(tarea, usuario.getId());
        return "redirect:/tareas";
    }

    // Buscador usado en la prueba de SQL Injection del Paso 8
    @GetMapping("/buscar")
    public String buscar(@RequestParam(defaultValue = "") String texto, Model model) {
        model.addAttribute("texto", texto);
        model.addAttribute("resultados", service.buscar(texto));
        return "tareas/buscar";
    }
}
