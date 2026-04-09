import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.Set;

@Service
public class WindowsSeverityService {

    private static final Set<String> HIGH_RISK_GROUPS = Set.of("administrators", "domain admins", "enterprise admins");

    private static final Map<Integer, Double> EVENT_ID_FLOORS = Map.of(
        4625, 7.5,
        4720, 8.5,
        4722, 8.0,
        4724, 8.5,
        4732, 9.0,
        4688, 4.0,
        1102, 10.0
    );

    public double calculateSeverity(JsonNode record) {
        int eventId = record.path("EventID").asInt(0);
        String eventType = record.path("EventType").asText("").toUpperCase();
        JsonNode data = record.path("EventData");
        
        String targetUser = data.path("TargetUserName").asText("").toLowerCase();
        String targetGroup = data.path("TargetGroupName").asText("").toLowerCase();
        String subjectUser = data.path("SubjectUserName").asText("").toLowerCase();

        double baseScore = EVENT_ID_FLOORS.getOrDefault(eventId, 3.0);
        double multiplier = 1.0;

        if (eventType.contains("FAILURE")) {
            multiplier *= 1.3;
        }

        if (HIGH_RISK_GROUPS.contains(targetGroup) || targetGroup.contains("admin")) {
            multiplier *= 1.4;
        }

        if (!subjectUser.isEmpty() && !targetUser.isEmpty() && !subjectUser.equals(targetUser)) {
            multiplier *= 1.2;
        }

        double finalScore = baseScore * multiplier;

        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }
}

