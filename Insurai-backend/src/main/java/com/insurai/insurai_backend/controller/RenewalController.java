package com.insurai.insurai_backend.controller;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.insurai.insurai_backend.config.JwtUtil;
import com.insurai.insurai_backend.model.Policy;
import com.insurai.insurai_backend.model.RenewalConfig;
import com.insurai.insurai_backend.model.RenewalHistory;
import com.insurai.insurai_backend.service.RenewalService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/admin/renewals")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class RenewalController {

    private final RenewalService renewalService;
    private final JwtUtil jwtUtil;

    // ==================== Get Renewal Configuration ====================
    @GetMapping("/config")
    public ResponseEntity<?> getRenewalConfig(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            RenewalConfig config = renewalService.getRenewalConfiguration();
            return ResponseEntity.ok(new RenewalConfigDTO(config));

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching renewal config: " + e.getMessage());
        }
    }

    // ==================== Update Renewal Configuration ====================
    @PutMapping("/config")
    public ResponseEntity<?> updateRenewalConfig(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody Map<String, Object> request) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            String token = authHeader.substring(7).trim();
            String adminEmail = jwtUtil.extractEmail(token);

            Boolean alertsEnabled = request.containsKey("alertsEnabled") ?
                    (Boolean) request.get("alertsEnabled") : null;
            Integer firstAlertDays = request.containsKey("firstAlertDays") ?
                    ((Number) request.get("firstAlertDays")).intValue() : null;
            Integer secondAlertDays = request.containsKey("secondAlertDays") ?
                    ((Number) request.get("secondAlertDays")).intValue() : null;
            Integer finalAlertDays = request.containsKey("finalAlertDays") ?
                    ((Number) request.get("finalAlertDays")).intValue() : null;
            Boolean autoExpireEnabled = request.containsKey("autoExpireEnabled") ?
                    (Boolean) request.get("autoExpireEnabled") : null;

            // Validate alert days order
            if (firstAlertDays != null && secondAlertDays != null && finalAlertDays != null) {
                if (!(firstAlertDays > secondAlertDays && secondAlertDays > finalAlertDays)) {
                    return ResponseEntity.badRequest()
                            .body("Alert days must be in descending order: firstAlertDays > secondAlertDays > finalAlertDays");
                }
            }

            RenewalConfig config = renewalService.updateRenewalConfiguration(
                    alertsEnabled, firstAlertDays, secondAlertDays, finalAlertDays,
                    autoExpireEnabled, adminEmail);

            return ResponseEntity.ok(new RenewalConfigDTO(config));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error updating renewal config: " + e.getMessage());
        }
    }

    // ==================== Get Upcoming Renewals ====================
    @GetMapping("/upcoming")
    public ResponseEntity<?> getUpcomingRenewals(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam(defaultValue = "30") int daysAhead) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            List<Policy> policies = renewalService.getUpcomingRenewals(daysAhead);
            List<PolicyRenewalDTO> dtos = policies.stream()
                    .map(PolicyRenewalDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching upcoming renewals: " + e.getMessage());
        }
    }

    // ==================== Get Renewal Statistics ====================
    @GetMapping("/stats")
    public ResponseEntity<?> getRenewalStats(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            Map<String, Object> stats = renewalService.getRenewalStatistics();
            return ResponseEntity.ok(stats);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching renewal stats: " + e.getMessage());
        }
    }

    // ==================== Manual Renewal Check ====================
    @PostMapping("/check")
    public ResponseEntity<?> checkRenewals(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            String token = authHeader.substring(7).trim();
            String adminEmail = jwtUtil.extractEmail(token);

            Map<String, Object> result = renewalService.executeRenewalJobManually(adminEmail);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error running renewal check: " + e.getMessage());
        }
    }

    // ==================== Manually Trigger Renewal Job ====================
    @PostMapping("/execute-job")
    public ResponseEntity<?> executeRenewalJob(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            String token = authHeader.substring(7).trim();
            String adminEmail = jwtUtil.extractEmail(token);

            Map<String, Object> result = renewalService.executeRenewalJobManually(adminEmail);
            return ResponseEntity.ok(result);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error executing renewal job: " + e.getMessage());
        }
    }

    // ==================== Renew a Policy ====================
    @PostMapping("/policies/{policyId}/renew")
    public ResponseEntity<?> renewPolicy(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long policyId,
            @RequestBody Map<String, String> request) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            String token = authHeader.substring(7).trim();
            String adminEmail = jwtUtil.extractEmail(token);

            String newRenewalDateStr = request.get("newRenewalDate");
            if (newRenewalDateStr == null || newRenewalDateStr.isEmpty()) {
                return ResponseEntity.badRequest().body("newRenewalDate is required");
            }

            LocalDate newRenewalDate = LocalDate.parse(newRenewalDateStr);

            if (newRenewalDate.isBefore(LocalDate.now())) {
                return ResponseEntity.badRequest().body("New renewal date must be in the future");
            }

            Policy policy = renewalService.renewPolicy(policyId, newRenewalDate, adminEmail);
            return ResponseEntity.ok(new PolicyRenewalDTO(policy));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error renewing policy: " + e.getMessage());
        }
    }

    // ==================== Get Renewal History for a Policy ====================
    @GetMapping("/policies/{policyId}/history")
    public ResponseEntity<?> getRenewalHistory(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long policyId) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            List<RenewalHistory> history = renewalService.getRenewalHistory(policyId);
            List<RenewalHistoryDTO> dtos = history.stream()
                    .map(RenewalHistoryDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching renewal history: " + e.getMessage());
        }
    }

    // ==================== Helper Methods ====================
    private boolean validateAdminToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }
        String token = authHeader.substring(7).trim();
        String role = jwtUtil.extractRole(token);
        return "ADMIN".equalsIgnoreCase(role);
    }

    // ==================== DTOs ====================
    public static class RenewalConfigDTO {
        public Long id;
        public Boolean alertsEnabled;
        public Integer firstAlertDays;
        public Integer secondAlertDays;
        public Integer finalAlertDays;
        public Boolean autoExpireEnabled;
        public String lastModifiedBy;
        public String lastModifiedAt;

        public RenewalConfigDTO(RenewalConfig config) {
            this.id = config.getId();
            this.alertsEnabled = config.getAlertsEnabled();
            this.firstAlertDays = config.getFirstAlertDays();
            this.secondAlertDays = config.getSecondAlertDays();
            this.finalAlertDays = config.getFinalAlertDays();
            this.autoExpireEnabled = config.getAutoExpireEnabled();
            this.lastModifiedBy = config.getLastModifiedBy();
            this.lastModifiedAt = config.getLastModifiedAt() != null ?
                    config.getLastModifiedAt().toString() : null;
        }
    }

    public static class PolicyRenewalDTO {
        public Long id;
        public String policyNumber;
        public String policyName;
        public String policyType;
        public String providerName;
        public Double coverageAmount;
        public LocalDate renewalDate;
        public String policyStatus;
        public long daysUntilRenewal;

        public PolicyRenewalDTO(Policy policy) {
            this.id = policy.getId();
            this.policyNumber = policy.getPolicyNumber();
            this.policyName = policy.getPolicyName();
            this.policyType = policy.getPolicyType();
            this.providerName = policy.getProviderName();
            this.coverageAmount = policy.getCoverageAmount();
            this.renewalDate = policy.getRenewalDate();
            this.policyStatus = policy.getPolicyStatus();
            this.daysUntilRenewal = java.time.temporal.ChronoUnit.DAYS.between(
                    LocalDate.now(), policy.getRenewalDate());
        }
    }

    public static class RenewalHistoryDTO {
        public Long id;
        public Long policyId;
        public LocalDate oldRenewalDate;
        public LocalDate newRenewalDate;
        public String renewedBy;
        public String renewalType;
        public String renewedAt;

        public RenewalHistoryDTO(RenewalHistory history) {
            this.id = history.getId();
            this.policyId = history.getPolicy() != null ? history.getPolicy().getId() : null;
            this.oldRenewalDate = history.getOldRenewalDate();
            this.newRenewalDate = history.getNewRenewalDate();
            this.renewedBy = history.getRenewedBy();
            this.renewalType = history.getRenewalType();
            this.renewedAt = history.getRenewedAt() != null ? history.getRenewedAt().toString() : null;
        }
    }
}

