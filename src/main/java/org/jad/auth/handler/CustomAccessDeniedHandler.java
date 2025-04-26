package org.jad.auth.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
//        System.out.println(">>> AccessDeniedHandler triggered !");

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");

        String json = """
                {
                    "code": 403,
                    "error": "Accès refusé",
                    "message": "Vous n'avez pas la permission d'accéder à cette ressource.",
                    "timestamp": "%s"
                }
                """.formatted(java.time.LocalDateTime.now());

        response.getWriter().write(json);
    }
}

