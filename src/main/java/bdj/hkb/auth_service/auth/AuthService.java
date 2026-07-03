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
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
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
    public User registerLocalUser(LocalSignupRequest request) {

        log.info(
                "Signup request for {} under client {}",
                request.email(),
                request.clientId()
        );

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
                .isActive(false)
                .isEmailVerified(false)
                .build();

        User savedUser;
        try {
            savedUser = userRepository.save(user);
        } catch (DataIntegrityViolationException e) {
            throw new UserAlreadyExistsException("User already exists");
        }
        log.info(
                "User {} registered under client {}",
                savedUser.getId(),
                request.clientId()
        );

        UserRole defaultRole = UserRole.builder()
                .user(savedUser)
                .client(client)
                .role("ROLE_USER")
                .build();
        userRoleRepository.save(defaultRole);
        log.info(
                "Assigned default ROLE_USER to {}",
                savedUser.getId()
        );

        return savedUser;
    }

    // -------------------------------------------------------------------
    // LOCAL LOGIN
    // -------------------------------------------------------------------
    public AuthResponse authenticateLocalUser(LocalLoginRequest request) {

        log.info(
                "Login attempt for {} under client {}",
                request.email(),
                request.clientId()
        );
        Client client = clientRepository.findByIdAndIsActiveTrue(request.clientId())
                        .orElseThrow(() -> new ClientNotFoundException("Client not found"));

        // 2. Locate User
        User user = userRepository.findByClientIdAndEmail(request.clientId(), request.email())
                .orElseThrow(() -> new RuntimeException(
                        "User not found for ClientID: " + request.clientId() + " and Email: " + request.email()
                ));
        if(!user.getAuthProvider().equals("local")){
            throw new InvalidCredentialsException("Wrong auth provider: Required local");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        if (!user.getIsEmailVerified()) {
            throw new EmailNotVerifiedException("Please verify your email address before logging in.");
        }

        if (!user.getIsActive()) {
            throw new AccountDisabledException("Account is disabled");
        }

        List<String> roles = userRoleRepository
                .findByUserIdAndClientId(user.getId(), request.clientId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        log.info(
                "User {} authenticated successfully under client {}",
                user.getId(),
                request.clientId()
        );
        return issueTokens(user.getId().toString(), request.clientId().toString(), roles);
    }

    // -------------------------------------------------------------------
    // LOGOUT
    // -------------------------------------------------------------------
    public void logout(String accessToken) {
        String jti = jwtUtil.extractJti(accessToken);
        String userId = jwtUtil.extractUserId(accessToken);
        log.info(
                "Logout requested for user {}",
                userId
        );

        String clientId = jwtUtil.extractClientId(accessToken);
        long remainingMillis = jwtUtil.extractExpiration(accessToken).getTime() - System.currentTimeMillis();
        tokenBlacklistService.blacklist(jti, remainingMillis);
        refreshTokenService.revoke(userId, clientId);
        log.info(
                "Revoked refresh token and blacklisted access token for user {}",
                userId
        );
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
        String clientId = jwtUtil.extractClientId(refreshToken);

        log.info(
                "Refresh token validated for user {}",
                userId
        );

        if (!refreshTokenService.isValid(userId, clientId, jti)) {
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
        String refreshToken = jwtUtil.generateRefreshToken(userId, clientId);

        String refreshJti = jwtUtil.extractJti(refreshToken);
        long refreshExpiry = jwtUtil.extractExpiration(refreshToken).getTime() - System.currentTimeMillis();
        refreshTokenService.store(userId, clientId, refreshJti, refreshExpiry);

        log.info(
                "Issued access and refresh tokens for user {} under client {}",
                userId,
                clientId
        );

        return new AuthResponse(accessToken, refreshToken, "Bearer");
    }
}