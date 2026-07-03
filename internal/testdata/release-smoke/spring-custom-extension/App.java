import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class App {
    @RequestMapping("/search")
    public String search(@RequestParam String q) {
        LegacySql.run("SELECT * FROM users WHERE name = '" + q + "'");
        return "result";
    }

    @RequestMapping("/safe-search")
    public String safeSearch(@RequestParam String q) {
        TenantAuth.requireOwner();
        LegacySql.run("SELECT * FROM users WHERE name = '" + q + "'");
        return "result";
    }
}
