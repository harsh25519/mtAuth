package bdj.hkb.auth_service.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

@Service
public class JwtUtilService {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    @Value("${jwt.access-expiration}")
    private Long ACCESS_EXPIRATION_MS;

    @Value("${jwt.refresh-expiration}")
    private Long REFRESH_EXPIRATION_MS;

    public String generateAccessToken(String userId, String clientId, List<String> roles){
        return Jwts.builder()
                .claims()
                .add("clientId", clientId)
                .add("roles", roles)
                .add("type", "access")
                .id(UUID.randomUUID().toString())   // jti — unique per token
                .subject(userId)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + ACCESS_EXPIRATION_MS))
                .and()
                .signWith(getSigningKey())
                .compact();
    }

    // -------------------------------------------------------------------
    // REFRESH TOKEN — new, minimal payload, longer expiry
    // -------------------------------------------------------------------
    public String generateRefreshToken(String userId) {
        return Jwts.builder()
                .claims()
                .add("type", "refresh")
                .id(UUID.randomUUID().toString())
                .subject(userId)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_EXPIRATION_MS))
                .and()
                .signWith(getSigningKey())
                .compact();
    }

    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("type", String.class));
    }

    private SecretKey getSigningKey() {
        byte[] bytesKey = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(bytesKey);
    }

    public String extractUserId(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractClientId(String token) {
        return extractClaim(token, claims -> claims.get("clientId", String.class));
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> claims.get("roles", List.class));
    }

    // Extract any claim
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validateToken(String token) {
        try {
            extractAllClaims(token); // throws if invalid or expired
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

}
