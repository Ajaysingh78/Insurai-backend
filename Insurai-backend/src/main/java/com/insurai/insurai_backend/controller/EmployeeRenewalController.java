package com.insurai.insurai_backend.controller;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.insurai.insurai_backend.config.JwtUtil;
import com.insurai.insurai_backend.model.Employee;
import com.insurai.insurai_backend.model.Enrollment;
import com.insurai.insurai_backend.model.Policy;
import com.insurai.insurai_backend.repository.EmployeeRepository;
import com.insurai.insurai_backend.repository.EnrollmentRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/employee/renewals")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class EmployeeRenewalController {

    private final EnrollmentRepository enrollmentRepository;
    private final EmployeeRepository employeeRepository;
    private final JwtUtil jwtUtil;

    // ==================== Get My Policy Renewals ====================
    @GetMapping("/my-policies")
    public ResponseEntity<?> getMyPolicyRenewals(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(403).body("Missing or invalid Authorization header");
            }

            String token = authHeader.substring(7).trim();
            String email = jwtUtil.extractEmail(token);
            String role = jwtUtil.extractRole(token);

            if (!"EMPLOYEE".equalsIgnoreCase(role)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an employee");
            }

            Employee employee = employeeRepository.findByEmail(email).orElse(null);
            if (employee == null) {
                return ResponseEntity.status(403).body("Invalid token: Employee not found");
            }

            // Get active enrollments for the employee
            List<Enrollment> activeEnrollments = enrollmentRepository.findActiveEnrollmentsByEmployeeId(employee.getId());

            // Map to policy renewal DTOs
            List<PolicyRenewalDTO> renewalDTOs = activeEnrollments.stream()
                    .filter(e -> e.getPolicy() != null && e.getPolicy().getRenewalDate() != null)
                    .map(enrollment -> new PolicyRenewalDTO(enrollment.getPolicy(), enrollment))
                    .collect(Collectors.toList());

            return ResponseEntity.ok(renewalDTOs);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching policy renewals: " + e.getMessage());
        }
    }

    // ==================== DTO ====================
    public static class PolicyRenewalDTO {
        public Long id;
        public Long policyId;
        public String policyName;
        public String policyType;
        public String policyNumber;
        public String providerName;
        public Double coverageAmount;
        public Double premiumAmount;
        public LocalDate currentExpiryDate;
        public LocalDate effectiveDate;
        public String coverageType;
        public String status;
        public Long daysUntilExpiry;

        public PolicyRenewalDTO(Policy policy, Enrollment enrollment) {
            this.id = enrollment.getId();
            this.policyId = policy.getId();
            this.policyName = policy.getPolicyName();
            this.policyType = policy.getPolicyType();
            this.policyNumber = policy.getPolicyNumber();
            this.providerName = policy.getProviderName();
            this.coverageAmount = policy.getCoverageAmount();
            this.premiumAmount = enrollment.getPremiumAmount();
            this.currentExpiryDate = policy.getRenewalDate();
            this.effectiveDate = enrollment.getEffectiveDate();
            this.coverageType = enrollment.getCoverageType();
            this.status = enrollment.getStatus();

            if (policy.getRenewalDate() != null) {
                this.daysUntilExpiry = ChronoUnit.DAYS.between(LocalDate.now(), policy.getRenewalDate());
            } else {
                this.daysUntilExpiry = null;
            }
        }
    }
}

