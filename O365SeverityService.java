import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.Set;

@Service
public class O365SeverityService {

    private static final String CORP_DOMAIN = "@contoso.com";
    private static final Set<String> SCRIPT_TOOLS = Set.of("python", "curl", "postman", "powershell", "java");

    private static final Map<String, Double> EXACT_MAP = Map.of(
        "newinboxrule", 10.0,
        "addrolegroupmember", 10.0,
        "userloginfailed", 8.5,
        "filedeleted", 7.0,
        "mailitemsaccessed", 6.5,
        "filedownloaded", 6.5
    );

    private static final Map<String, Double> WORKLOAD_FLOORS = Map.of(
        "azureactivedirectory", 5.0,
        "exchange", 5.5,
        "sharepoint", 5.0,
        "onedrive", 5.0,
        "securitycompliance", 8.5,
        "microsoftteams", 4.5
    );

    public double calculateSeverity(JsonNode record) {
        String operation = record.path("Operation").asText("")
                .trim()
                .toLowerCase()
                .replaceAll("[\\s_-]+", "");

        if (operation.isEmpty()) return 1.0;

        String workload = record.path("Workload").asText("").trim().toLowerCase();
        
        String userId = record.path("UserId").asText("").trim().toLowerCase();
        if (userId.isEmpty()) {
            userId = record.path("Actor").path("ID").asText("").trim().toLowerCase();
        }

        String resultStatus = record.path("ResultStatus").asText("").trim().toLowerCase();
        int userType = record.path("UserType").asInt(0);

        String userAgent = record.path("userAgent").asText("").toLowerCase();
        if (userAgent.isEmpty()) {
            JsonNode extProps = record.path("ExtendedProperties");
            if (extProps.isArray()) {
                for (JsonNode prop : extProps) {
                    if ("UserAgent".equalsIgnoreCase(prop.path("Name").asText())) {
                        userAgent = prop.path("Value").asText().toLowerCase();
                        break;
                    }
                }
            }
        }

        boolean isExternal = userId.contains("@") && !userId.endsWith(CORP_DOMAIN);
        boolean isScript = SCRIPT_TOOLS.stream().anyMatch(userAgent::contains);
        boolean isFailure = resultStatus.contains("fail") || resultStatus.contains("error");

        double baseScore = EXACT_MAP.getOrDefault(operation, 
                           WORKLOAD_FLOORS.getOrDefault(workload, 3.0));

        if (isExternal && isFailure && isScript) {
            baseScore = Math.max(baseScore, 9.5);
        } else if (isExternal && (isFailure || isScript)) {
            baseScore = Math.max(baseScore, 8.5);
        }

        if (operation.contains("download") && isExternal) {
            baseScore = Math.max(baseScore, 8.5);
        }

        double multiplier = 1.0;
        if (userType == 2 && baseScore >= 6.0) multiplier *= 1.3;
        if (isScript) multiplier *= 1.4;
        if (isExternal) multiplier *= 1.4;
        if (isFailure) multiplier *= 1.2;

        double finalScore = baseScore * multiplier;

        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }
}