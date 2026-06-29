package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.OAuth2UserInfo;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final AuthService authService; // Assuming this contains your JWT generation logic

    @Transactional
    public AuthResponse processOAuthUser(Client client, OAuth2UserInfo userInfo, OAuthProvider provider) {

        // Using your existing optimized query logic
        User user = userRepository.findByClientIdAndEmail(client.getId(), userInfo.email())
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .client(client)
                            .email(userInfo.email())
                            .authProvider(provider.name()) // Safely use the Enum name
                            .providerId(userInfo.providerId())
                            .isActive(true)
                            .build();

                    User savedUser = userRepository.save(newUser);

                    userRoleRepository.save(UserRole.builder()
                            .user(savedUser)
                            .client(client)
                            .role("ROLE_USER")
                            .build());

                    return savedUser;
                });

        List<String> roles = userRoleRepository.findByUserIdAndClientId(user.getId(), client.getId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        return authService.issueTokens(user.getId().toString(), client.getId().toString(), roles);
    }
}