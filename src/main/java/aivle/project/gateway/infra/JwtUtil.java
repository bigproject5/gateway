package aivle.project.gateway.infra;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;

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

            System.out.println("[" + now + "]" + "Valid token: " + claims.get("role") + "-" + claims.get("id"));
            return false;

        } catch (ExpiredJwtException e) {
            System.out.println("[" + now + "]" + "Token expired: " + e.getMessage());
        } catch (JwtException e) {
            System.out.println("[" + now + "]" + "Token forgery or other errors: " + e.getMessage());
        }
        return true;
    }
}
