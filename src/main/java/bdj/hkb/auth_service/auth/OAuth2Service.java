package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.exceptionHandler.InvalidOAuthProviderException;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuth2Service {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final AuthService authService;

    @Transactional
    public AuthResponse processOAuthUser(Client client, OAuth2UserInfo userInfo, OAuthProvider provider) {

        log.info(
                "Processing OAuth login under client {} using provider {}",
                client.getId(),
                provider
        );

        // Using your existing optimized query logic
        User user = userRepository.findByClientIdAndEmail(client.getId(), userInfo.email())
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .client(client)
                            .email(userInfo.email())
                            .authProvider(provider.name()) // Safely use the Enum name
                            .providerId(userInfo.providerId())
                            .isActive(true)
                            .isEmailVerified(true)
                            .build();

                    User savedUser = userRepository.save(newUser);

                    log.info(
                            "Created new OAuth user {} under client {} using provider {}",
                            savedUser.getId(),
                            client.getId(),
                            provider
                    );

                    userRoleRepository.save(UserRole.builder()
                            .user(savedUser)
                            .client(client)
                            .role("ROLE_USER")
                            .build());

                    log.info(
                            "Assigned default ROLE_USER to OAuth user {}",
                            savedUser.getId()
                    );

                    return savedUser;
                });

        if (!provider.name().equals(user.getAuthProvider())) {
            throw new InvalidOAuthProviderException("Account is registered using a different authentication provider.");
        }

        log.info(
                "User {} authenticated using {}",
                user.getId(),
                provider
        );

        List<String> roles = userRoleRepository.findByUserIdAndClientId(user.getId(), client.getId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        return authService.issueTokens(user.getId().toString(), client.getId().toString(), roles);
    }
}