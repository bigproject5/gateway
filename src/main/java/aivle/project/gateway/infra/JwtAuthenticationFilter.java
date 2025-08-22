package aivle.project.gateway.infra;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        List<String> authRequiredPaths = List.of(
                "/api/operation/workers/**",
                "/api/operation/notices/**",
                "/api/operation/me",
                "/api/vehicleaudit/**",
                "/api/taskreports/**"
        );

        boolean isAuthRequired = authRequiredPaths.stream()
                .anyMatch(p -> pathMatcher.match(p, path));



//        if (!isAuthRequired) {
//            log.info("Path {} does not require authentication.", path);
//            return chain.filter(exchange);
//        }
//
//        log.info("Path {} requires authentication.", path);

        String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")){
            return chain.filter(exchange);
        }

        String token = authorizationHeader.substring(7);
        if (jwtUtil.isExpired(token)) {
            return handleUnauthorized(exchange, "Token is expired or invalid");
        }

        Long userId = jwtUtil.getUserId(token);
        String role = jwtUtil.getUserRole(token);
        String name = jwtUtil.getUserInfo(token, "name");
        String taskType = jwtUtil.getUserInfo(token, "taskType");

        log.info("user id {}, role {}, name {}", userId, role, name);

        String encodedName = URLEncoder.encode(name, StandardCharsets.UTF_8);
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", userId.toString())
                .header("X-User-Role", role)
                .header("X-User-Name", encodedName)
                .header("X-User-Task-Type", taskType)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        return chain.filter(mutatedExchange);
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add("Content-Type", "application/json");
        String errorMessage = "{\"message\":\"" + message + "\"}";
        DataBuffer buffer = response.bufferFactory().wrap(errorMessage.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }
}