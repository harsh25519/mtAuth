package bdj.hkb.auth_service.user;

import bdj.hkb.auth_service.exceptionHandler.UserNotFoundException;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Value("${platform.master-client-id}")
    private String masterClientId;

    public Page<UserResponse> getAllUsers(String tokenClientId, Pageable pageable) {
        // SECURITY: Only the platform admin can fetch everyone
        if (!masterClientId.equals(tokenClientId)) {
            throw new AccessDeniedException("Unauthorized: Only platform admins can view all users globally.");
        }

        Page<User> userPage = userRepository.findAllWithClient(pageable);
        return mapToResponsePage(userPage);
    }

    public Page<UserResponse> getUsersByClientId(UUID requestedClientId, String tokenClientId, Pageable pageable) {
        // SECURITY: You can only view users in your own tenant (or if you are the master admin)
        if (!requestedClientId.toString().equals(tokenClientId) && !masterClientId.equals(tokenClientId)) {
            throw new AccessDeniedException("Unauthorized: You cannot view users belonging to another tenant.");
        }

        Page<User> userPage = userRepository.findByClientIdWithClient(requestedClientId, pageable);
        return mapToResponsePage(userPage);
    }

    // --- YOUR PERFECT MAPPING LOGIC BELOW ---

    private Page<UserResponse> mapToResponsePage(Page<User> userPage) {
        List<User> users = userPage.getContent();
        Map<UUID, List<String>> rolesByUserId = fetchRolesGrouped(users);

        List<UserResponse> responses = users.stream()
                .map(user -> toResponse(user, rolesByUserId.getOrDefault(user.getId(), List.of())))
                .toList();

        return new PageImpl<>(responses, userPage.getPageable(), userPage.getTotalElements());
    }

    private Map<UUID, List<String>> fetchRolesGrouped(List<User> users) {
        List<UUID> userIds = users.stream().map(User::getId).toList();
        if (userIds.isEmpty()) return Map.of();

        return userRoleRepository.findByUserIds(userIds).stream()
                .collect(Collectors.groupingBy(
                        ur -> ur.getUser().getId(),
                        Collectors.mapping(UserRole::getRole, Collectors.toList())
                ));
    }

    // --- Single User Lookup ---
    public UserResponse getUserById(UUID requestedUserId, String tokenClientId) {

        // 1. Fetch the user
        User user = userRepository.findById(requestedUserId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        // 2. SECURITY CHECK: Prevent cross-tenant ID guessing
        String targetUserClientId = user.getClient().getId().toString();
        if (!targetUserClientId.equals(tokenClientId) && !masterClientId.equals(tokenClientId)) {
            throw new AccessDeniedException("Unauthorized: You do not have permission to view this user's details.");
        }

        // 3. Fetch roles for this specific user
        List<String> roles = userRoleRepository.findByUserIdAndClientId(user.getId(), user.getClient().getId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        // 4. Map to DTO
        return toResponse(user, roles);
    }

    private UserResponse toResponse(User user, List<String> roles) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getClient().getId(),
                user.getIsActive(),
                user.getAuthProvider(),
                roles,
                user.getCreatedAt()
        );
    }
}
