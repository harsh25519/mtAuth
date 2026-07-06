package bdj.hkb.auth_service.health;

import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthController {
    @GetMapping("/ping")
    @Transactional(propagation = Propagation.NEVER)
    public String keepAlive() {
        return "OK";
    }
}
