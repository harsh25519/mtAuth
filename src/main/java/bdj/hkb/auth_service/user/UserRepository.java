package bdj.hkb.auth_service.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByClientIdAndEmail(UUID clientId, String email);
    boolean existsByClientIdAndEmail(UUID clientId, String email);

    Optional<User> findByProviderIdAndAuthProvider(String providerId, String authProvider);
}