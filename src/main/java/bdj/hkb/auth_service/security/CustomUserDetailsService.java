package bdj.hkb.auth_service.security;

import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        List<String> roles = userRoleRepository
                .findByUserIdAndClientId(user.getId(), user.getClient().getId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        return new CustomUserDetails(user, roles);
    }
}
