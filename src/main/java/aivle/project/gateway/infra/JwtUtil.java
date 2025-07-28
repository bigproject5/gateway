package aivle.project.gateway.infra;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;

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

    public boolean isExpired(String token){
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            System.out.println("Valid token: " + claims.get("role") + "-" + claims.get("id"));
            return false;

        } catch (ExpiredJwtException e) {
            System.out.println("Token expired: " + e.getMessage());
        } catch (JwtException e) {
            System.out.println("Token forgery or other errors: " + e.getMessage());
        }
        return true;
    }
}
