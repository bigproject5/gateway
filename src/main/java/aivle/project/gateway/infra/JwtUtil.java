package aivle.project.gateway.infra;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;

@Slf4j
@Component
public class JwtUtil {
    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.expiredMs}")
    private Long expirationTime;

    private Key getKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public Long getUserId(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("id", Long.class);
    }

    public String getUserRole(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("role", String.class);
    }

    public String getUserInfo(String token, String type){
        return Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get(type, String.class);
    }

    public boolean isExpired(String token){
        LocalDateTime now = LocalDateTime.now();
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            log.info("[{}]Valid token: {}-{}", now, claims.get("role"), claims.get("id"));
            return false;

        } catch (ExpiredJwtException e) {
            log.info("[{}]Token expired: {}", now, e.getMessage());
        } catch (JwtException e) {
            log.info("[{}]Token forgery or other errors: {}", now, e.getMessage());
        }
        return true;
    }
}
