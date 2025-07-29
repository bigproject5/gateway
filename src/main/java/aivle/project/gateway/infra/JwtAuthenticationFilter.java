package aivle.project.gateway.infra;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements WebFilter {

    private final JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if(authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")){
            return chain.filter(exchange);
        }

        String token = authorizationHeader.substring(7);
        if(jwtUtil.isExpired(token)){
            return chain.filter(exchange);
        }

        Long userId = jwtUtil.getUserId(token);
        String role = jwtUtil.getUserRole(token);
        String name = jwtUtil.getUserInfo(token, "name");


        log.info("user id {}, role {}, name {}", userId, role, name);

        String encodedName = URLEncoder.encode(name, StandardCharsets.UTF_8);
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", userId.toString())
                .header("X-User-Role", role)
                .header("X-User-Name", encodedName)
                .build();

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(mutatedRequest)
                .build();

        return chain.filter(mutatedExchange);
    }
}
