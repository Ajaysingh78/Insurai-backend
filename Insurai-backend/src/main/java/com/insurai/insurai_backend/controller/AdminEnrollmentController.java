package com.insurai.insurai_backend.controller;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.insurai.insurai_backend.config.JwtUtil;
import com.insurai.insurai_backend.model.Enrollment;
import com.insurai.insurai_backend.service.EnrollmentService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/admin/enrollments")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class AdminEnrollmentController {

    private final EnrollmentService enrollmentService;
    private final JwtUtil jwtUtil;

    // ==================== Get All Enrollments ====================
    @GetMapping("/all")
    public ResponseEntity<?> getAllEnrollments(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            List<Enrollment> enrollments = enrollmentService.getAllEnrollments();
            List<EnrollmentDTO> dtos = enrollments.stream()
                    .map(EnrollmentDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching enrollments: " + e.getMessage());
        }
    }

    // ==================== Get Enrollment Statistics ====================
    @GetMapping("/stats")
    public ResponseEntity<?> getEnrollmentStatistics(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            Map<String, Object> stats = enrollmentService.getEnrollmentStatistics();
            return ResponseEntity.ok(stats);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching statistics: " + e.getMessage());
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

    // ==================== DTO ====================
    public static class EnrollmentDTO {
        public Long id;
        public Long employeeId;
        public String employeeName;
        public String employeeEmail;
        public Long policyId;
        public String policyName;
        public String policyType;
        public String status;
        public String coverageType;
        public Double premiumAmount;
        public LocalDate enrollmentDate;
        public LocalDate effectiveDate;
        public String assignedHrName;

        public EnrollmentDTO(Enrollment enrollment) {
            this.id = enrollment.getId();
            this.employeeId = enrollment.getEmployee() != null ? enrollment.getEmployee().getId() : null;
            this.employeeName = enrollment.getEmployee() != null ? enrollment.getEmployee().getName() : null;
            this.employeeEmail = enrollment.getEmployee() != null ? enrollment.getEmployee().getEmail() : null;
            this.policyId = enrollment.getPolicy() != null ? enrollment.getPolicy().getId() : null;
            this.policyName = enrollment.getPolicy() != null ? enrollment.getPolicy().getPolicyName() : null;
            this.policyType = enrollment.getPolicy() != null ? enrollment.getPolicy().getPolicyType() : null;
            this.status = enrollment.getStatus();
            this.coverageType = enrollment.getCoverageType();
            this.premiumAmount = enrollment.getPremiumAmount();
            this.enrollmentDate = enrollment.getEnrollmentDate();
            this.effectiveDate = enrollment.getEffectiveDate();
            this.assignedHrName = enrollment.getAssignedHr() != null ? enrollment.getAssignedHr().getName() : null;
        }
    }
}

