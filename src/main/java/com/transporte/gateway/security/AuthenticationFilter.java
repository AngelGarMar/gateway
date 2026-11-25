package com.transporte.gateway.security;

import com.transporte.gateway.response.Response;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
    private static final Logger log = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private ObjectMapper objectMapper;

    public AuthenticationFilter() { super(Config.class); }

    public static class Config {
        private String requiredRole;
        public String getRequiredRole() { return requiredRole; }
        public void setRequiredRole(String requiredRole) { this.requiredRole = requiredRole; }
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            log.info("validando presencia del encabezado Authorization");
            if (!request.getHeaders().containsHeader(HttpHeaders.AUTHORIZATION)) {
                log.info("no contiene el encabezado");
                Response response = new Response(HttpStatus.UNAUTHORIZED.value(), "Falta encabezado Authorization", HttpStatus.UNAUTHORIZED.getReasonPhrase(), "");
                return onError(exchange, response, HttpStatus.UNAUTHORIZED);
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            log.info("validando el formato Bearer");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.info("no contiene el Bearer");
                Response response = new Response(HttpStatus.UNAUTHORIZED.value(), "Formato de token inválido", HttpStatus.UNAUTHORIZED.getReasonPhrase(), "");
                return onError(exchange, response, HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            log.info("validando firma del token");
            if (jwtUtil.isInvalid(token)) {
                log.info("token inválido");
                Response response = new Response(HttpStatus.UNAUTHORIZED.value(), "Token inválido", HttpStatus.UNAUTHORIZED.getReasonPhrase(), "");
                return onError(exchange, response, HttpStatus.UNAUTHORIZED);
            }
            log.info("validando expiración del token");
            if (jwtUtil.isExpired(token)) {
                log.info("token expirado");
                Response response = new Response(HttpStatus.UNAUTHORIZED.value(), "Token expirado", HttpStatus.UNAUTHORIZED.getReasonPhrase(), "");
                return onError(exchange, response, HttpStatus.UNAUTHORIZED);
            }

            log.info("se valida el rol requerido desde el yml");
            Claims claims = jwtUtil.getClaims(token);
            List<String> rolesToken = Arrays.stream(claims.get("authorities", String.class).replace("[", "").replace("]", "").replace("\"", "").split(","))
                    .map(String::trim).toList();
            log.info("roles del token: {}", rolesToken);
            List<String> rolesPermitidos = Arrays.stream(config.getRequiredRole().split(","))
                    .map(String::trim).toList();
            log.info("roles permitidos: {}", rolesPermitidos);
            log.info("se verifica si el usuario tiene al menos uno de los roles permitidos");
            boolean tienePermiso = rolesToken.stream().anyMatch(rolesPermitidos::contains);
            if (!tienePermiso) {
                log.info("usuario no autorizado para entrar a {}, requiere uno de: {}", path, rolesPermitidos);
                //se devuelve 403 forbidden cuando el token es válido pero no tiene permisos
                Response response = new Response(HttpStatus.FORBIDDEN.value(), "No tienes permisos para acceder a este recurso", HttpStatus.FORBIDDEN.getReasonPhrase(), "");
                return onError(exchange, response, HttpStatus.FORBIDDEN);
            }

            log.info("se propaga información de user y roles hacia el microservicio");
            log.info("user: {}", claims.getSubject());
            log.info("roles: {}", rolesToken);
            ServerHttpRequest modifiedRequest = request.mutate()
                    .headers(header -> {
                        header.remove("X-User-Id");
                        header.remove("X-User-Roles");
                        header.set("X-User-Id", claims.getSubject());
                        header.set("X-User-Roles", claims.get("authorities", String.class));
                    })
                    .build();
            return chain.filter(exchange.mutate().request(modifiedRequest).build());
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, Response err, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().set(HttpHeaders.CONTENT_TYPE, "application/json");
        String path = exchange.getRequest().getURI().getPath();
        err.setPath(path);
        byte[] bytes = objectMapper.writeValueAsBytes(err);
        DataBuffer dataBuffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(dataBuffer));
    }
}
