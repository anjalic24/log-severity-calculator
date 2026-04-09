import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.Set;

@Service
public class PaloAltoSeverityService {

    private static final Set<String> CRITICAL_ZONES = Set.of("trust", "dmz", "internal", "prod");
    private static final Set<String> DANGEROUS_APPS = Set.of("ssh", "telnet", "rdp", "ftp", "smb", "tftp");

    private static final Map<String, Double> SUBTYPE_FLOORS = Map.of(
        "threat", 8.5,
        "wildfire", 9.0,
        "vulnerability", 9.5,
        "url", 6.0,
        "traffic", 4.0
    );

    public double calculateSeverity(JsonNode record) {
        String type = record.path("type").asText("").toLowerCase();
        String subtype = record.path("subtype").asText("").toLowerCase();
        String action = record.path("action").asText("").toLowerCase();
        String app = record.path("app").asText("").toLowerCase();
        String threatName = record.path("threat_name").asText("").trim();
        int dport = record.path("dport").asInt(0);
        String dstZone = record.path("dst_zone").asText(record.path("to").asText("")).toLowerCase();

        double baseScore = SUBTYPE_FLOORS.getOrDefault(subtype, 
                           SUBTYPE_FLOORS.getOrDefault(type, 3.0));

        if (!threatName.isEmpty() && !threatName.equalsIgnoreCase("none")) {
            baseScore = Math.max(baseScore, 9.0);
        }

        double multiplier = 1.0;

        if (CRITICAL_ZONES.contains(dstZone)) {
            multiplier *= 1.3;
        }

        if (DANGEROUS_APPS.contains(app) || dport == 3389 || dport == 22 || dport == 445) {
            multiplier *= 1.2;
        }

        if (action.equals("allow") && baseScore >= 6.0) {
            multiplier *= 1.4;
        } else if (action.contains("deny") || action.contains("drop") || action.contains("block")) {
            multiplier *= 0.8;
        }

        double finalScore = baseScore * multiplier;
        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }
}

