package bdj.hkb.auth_service.role;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {
    List<UserRole> findByUserIdAndClientId(UUID userId, UUID clientId);

    @Query("SELECT ur FROM UserRole ur WHERE ur.user.id IN :userIds")
    List<UserRole> findByUserIds(@Param("userIds") List<UUID> userIds);
}
