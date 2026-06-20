package bdj.hkb.auth_service.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByClientIdAndEmail(UUID clientId, String email);

    boolean existsByClientIdAndEmail(UUID clientId, String email);

    Optional<User> findByProviderIdAndAuthProvider(String providerId, String authProvider);

    @EntityGraph(attributePaths = {"client"})
    @Query("SELECT u FROM User u")
    Page<User> findAllWithClient(Pageable pageable);

    @EntityGraph(attributePaths = {"client"})
    @Query("SELECT u FROM User u WHERE u.client.id = :clientId")
    Page<User> findByClientIdWithClient(@Param("clientId") UUID requestedClientId, Pageable pageable);

    Optional<User> findByIdAndClientId(UUID id, UUID clientId);
}