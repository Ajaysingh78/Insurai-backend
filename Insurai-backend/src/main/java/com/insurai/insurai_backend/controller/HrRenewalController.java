package com.insurai.insurai_backend.controller;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.insurai.insurai_backend.config.JwtUtil;
import com.insurai.insurai_backend.model.Policy;
import com.insurai.insurai_backend.service.RenewalService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/hr/renewals")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class HrRenewalController {

    private final RenewalService renewalService;
    private final JwtUtil jwtUtil;

    // ==================== Get Upcoming Renewals ====================
    @GetMapping("/upcoming")
    public ResponseEntity<?> getUpcomingRenewals(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam(defaultValue = "30") int daysAhead) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
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

    // ==================== Get My Employees Policy Renewals ====================
    @GetMapping("/my-employees")
    public ResponseEntity<?> getMyEmployeesRenewals(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
            }

            // Get all upcoming renewals (within 90 days)
            List<Policy> policies = renewalService.getUpcomingRenewals(90);
            List<PolicyRenewalDTO> dtos = policies.stream()
                    .map(PolicyRenewalDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching employee renewals: " + e.getMessage());
        }
    }

    // ==================== Helper Methods ====================
    private boolean validateHrToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }
        String token = authHeader.substring(7).trim();
        String role = jwtUtil.extractRole(token);
        return "HR".equalsIgnoreCase(role);
    }

    // ==================== DTO ====================
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
}

