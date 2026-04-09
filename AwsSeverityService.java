import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.Set;

@Service
public class AwsSeverityService {

    private static final Set<String> SCRIPT_TOOLS = Set.of("aws-cli", "boto3", "python", "curl", "postman");

    private static final Map<String, Double> EXACT_MAP = Map.of(
        "authorizesecuritygroupingress", 10.0,
        "putbucketpolicy", 10.0,
        "createaccesskey", 10.0,
        "createloginprofile", 9.5,
        "attachuserpolicy", 9.5,
        "deletetrail", 10.0,
        "stoplogging", 10.0,
        "deletebucket", 9.0,
        "terminateinstances", 8.5,
        "deleteuser", 9.0
    );

    private static final Map<String, Double> SERVICE_FLOORS = Map.of(
        "cloudtrail", 8.5,
        "iam", 7.5,
        "kms", 7.5,
        "sts", 6.5,
        "rds", 6.0,
        "s3", 5.5,
        "ec2", 4.5
    );

    public double calculateSeverity(JsonNode record) {
        String eventName = record.path("eventName").asText("")
                .trim().toLowerCase().replaceAll("[^a-z0-9]+", "");
        
        if (eventName.isEmpty()) return 1.0;

        String rawSource = record.path("eventSource").asText("").trim().toLowerCase();
        String normalizedSource = rawSource.replace(".amazonaws.com", "");

        JsonNode identity = record.path("userIdentity");
        String userType = identity.path("type").asText("");
        String arn = identity.path("arn").asText("").toLowerCase();
        
        String userName = identity.path("userName").asText("");
        if (userName.isEmpty()) {
            userName = identity.path("sessionContext").path("sessionIssuer").path("userName").asText("");
        }
        if (userName.isEmpty() && arn.contains("/")) {
            userName = arn.substring(arn.lastIndexOf("/") + 1);
        }

        String userAgent = record.path("userAgent").asText("").toLowerCase();
        boolean isScript = SCRIPT_TOOLS.stream().anyMatch(userAgent::contains);
        
        boolean isFailure = !record.path("errorCode").asText("").isEmpty();
        
        boolean isRoot = userType.equalsIgnoreCase("Root") || 
                         userName.equalsIgnoreCase("root") || 
                         arn.endsWith(":root");

        double baseScore = EXACT_MAP.getOrDefault(eventName, 
                           SERVICE_FLOORS.getOrDefault(normalizedSource, 3.0));

        double multiplier = 1.0;
        
        if (isRoot) multiplier *= 1.3;
        if (isFailure) multiplier *= 1.2;
        if (isScript) multiplier *= 1.2;

        double finalScore = baseScore * multiplier;

        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }
}