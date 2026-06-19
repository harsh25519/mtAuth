package bdj.hkb.auth_service.auth;

import bdj.hkb.auth_service.auth.dto.AuthResponse;
import bdj.hkb.auth_service.auth.dto.LocalLoginRequest;
import bdj.hkb.auth_service.auth.dto.LocalSignupRequest;
import bdj.hkb.auth_service.client.Client;
import bdj.hkb.auth_service.client.ClientRepository;
import bdj.hkb.auth_service.role.UserRole;
import bdj.hkb.auth_service.role.UserRoleRepository;
import bdj.hkb.auth_service.security.JwtUtilService;
import bdj.hkb.auth_service.user.User;
import bdj.hkb.auth_service.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.http.auth.InvalidCredentialsException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final UserRoleRepository userRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtilService jwtUtil;


    // -------------------------------------------------------------------
    // LOCAL SIGNUP
    // -------------------------------------------------------------------
    @Transactional
    public AuthResponse registerLocalUser(LocalSignupRequest request) {

        // 1. Verify client exists and is active
        Client client = clientRepository.findByIdAndIsActiveTrue(request.clientId())
                .orElseThrow(() -> new ClientNotFoundException("Invalid client"));

        // 2. Verify client secret — injected server-side by the consuming
        //    app's backend (BFF pattern), never exposed to the frontend
        if (!passwordEncoder.matches(request.clientSecret(), client.getClientSecret())) {
            throw new InvalidClientSecretException("Invalid client secret");
        }

        // 3. Ensure user doesn't already exist for this client
        if (userRepository.existsByClientIdAndEmail(request.clientId(), request.email())) {
            throw new UserAlreadyExistsException("User already exists");
        }

        // 4. Create and save user — guarded against race conditions
        //    via the (client_id, email) unique constraint at the DB level
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

        // 5. Assign default role
        UserRole defaultRole = UserRole.builder()
                .user(savedUser)
                .client(client)
                .role("ROLE_USER")
                .build();
        userRoleRepository.save(defaultRole);

        // 6. Generate JWT using the role just assigned
        String token = jwtUtil.generateToken(
                savedUser.getId().toString(),
                client.getId().toString(),
                List.of(defaultRole.getRole())
        );

        return new AuthResponse(token, "Bearer");
    }

    // -------------------------------------------------------------------
    // LOCAL LOGIN
    // -------------------------------------------------------------------
    public AuthResponse authenticateLocalUser(LocalLoginRequest request) throws InvalidCredentialsException {

        // 1. Find user scoped to this client (multi-tenant safe)
        User user = userRepository
                .findByClientIdAndEmail(request.clientId(), request.email())
                .   orElseThrow(() -> new InvalidCredentialsException("Invalid credentials"));

        // 2. Verify password manually — no AuthenticationManager involved
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }

        // 3. Check account is active
        if (!user.getIsActive()) {
            throw new AccountDisabledException("Account is disabled");
        }

        // 4. Fetch roles for this client
        List<String> roles = userRoleRepository
                .findByUserIdAndClientId(user.getId(), request.clientId())
                .stream()
                .map(UserRole::getRole)
                .toList();

        // 5. Generate JWT — use request.clientId() directly,
        //    avoids touching the lazy-loaded user.getClient() relation
        String token = jwtUtil.generateToken(
                user.getId().toString(),
                request.clientId().toString(),
                roles
        );

        return new AuthResponse(token, "Bearer");
    }
}

