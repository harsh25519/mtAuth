package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.LocalLoginRequest;
import bdj.hkb.auth_service.auth.dto.LocalSignupRequest;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.exceptionHandler.*;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.security.RefreshTokenService;
import bdj.hkb.auth_service.security.TokenBlacklistService;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtilService jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;
    private final RefreshTokenService refreshTokenService;

    // -------------------------------------------------------------------
    // LOCAL SIGNUP
    // -------------------------------------------------------------------
    @Transactional
    public AuthResponse registerLocalUser(LocalSignupRequest request) {

        Client client = clientRepository.findByIdAndIsActiveTrue(request.clientId())
                .orElseThrow(() -> new ClientNotFoundException("Invalid client"));

        if (!passwordEncoder.matches(request.clientSecret(), client.getClientSecret())) {
            throw new InvalidClientSecretException("Invalid client secret");
        }

        if (userRepository.existsByClientIdAndEmail(request.clientId(), request.email())) {
            throw new UserAlreadyExistsException("User already exists");
        }

        User user = User.builder()
                .client(client)
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .authProvider("local")
                .isActive(true)
                .build();

        User savedUser;
        try {
            savedUser = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new UserAlreadyExistsException("User already exists");
        }

        UserRole defaultRole = UserRole.builder()
                .user(savedUser)
                .client(client)
                .role("ROLE_USER")
                .build();
        userRoleRepository.save(defaultRole);

        return issueTokens(savedUser.getId().toString(), client.getId().toString(),
                List.of(defaultRole.getRole()));
    }

    // -------------------------------------------------------------------
    // LOCAL LOGIN
    // -------------------------------------------------------------------
    public AuthResponse authenticateLocalUser(LocalLoginRequest request) {

        User user = userRepository
                .findByClientIdAndEmail(request.clientId(), request.email())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid credentials"));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        if (!user.getIsActive()) {
            throw new AccountDisabledException("Account is disabled");
        }

        List<String> roles = userRoleRepository
                .findByUserIdAndClientId(user.getId(), request.clientId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        return issueTokens(user.getId().toString(), request.clientId().toString(), roles);
    }

    // -------------------------------------------------------------------
    // LOGOUT
    // -------------------------------------------------------------------
    public void logout(String accessToken) {
        String jti = jwtUtil.extractJti(accessToken);
        String userId = jwtUtil.extractUserId(accessToken);
        long remainingMillis = jwtUtil.extractExpiration(accessToken).getTime() - System.currentTimeMillis();
        tokenBlacklistService.blacklist(jti, remainingMillis);
        refreshTokenService.revoke(userId);
    }

    // -------------------------------------------------------------------
    // REFRESH
    // -------------------------------------------------------------------
    public AuthResponse refreshAccessToken(String refreshToken) {

        if (!jwtUtil.validateToken(refreshToken)) {
            throw new InvalidTokenException("Invalid or expired refresh token");
        }

        if (!"refresh".equals(jwtUtil.extractTokenType(refreshToken))) {
            throw new InvalidTokenException("Token is not a refresh token");
        }

        String userId = jwtUtil.extractUserId(refreshToken);
        String jti = jwtUtil.extractJti(refreshToken);

        if (!refreshTokenService.isValid(userId, jti)) {
            throw new InvalidTokenException("Refresh token has been revoked or replaced");
        }

        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        if (!user.getIsActive()) {
            throw new AccountDisabledException("Account is disabled");
        }

        List<String> roles = userRoleRepository
                .findByUserIdAndClientId(user.getId(), user.getClient().getId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        return issueTokens(userId, user.getClient().getId().toString(), roles);
    }

    // -------------------------------------------------------------------
    // SHARED — issues access + refresh token pair, stores refresh in Redis
    // -------------------------------------------------------------------
    AuthResponse issueTokens(String userId, String clientId, List<String> roles) {
        String accessToken = jwtUtil.generateAccessToken(userId, clientId, roles);
        String refreshToken = jwtUtil.generateRefreshToken(userId);

        String refreshJti = jwtUtil.extractJti(refreshToken);
        long refreshExpiry = jwtUtil.extractExpiration(refreshToken).getTime() - System.currentTimeMillis();
        refreshTokenService.store(userId, refreshJti, refreshExpiry);

        return new AuthResponse(accessToken, refreshToken, "Bearer");
    }
}