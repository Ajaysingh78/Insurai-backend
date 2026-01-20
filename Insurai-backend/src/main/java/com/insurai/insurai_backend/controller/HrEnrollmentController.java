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
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.insurai.insurai_backend.config.JwtUtil;
import com.insurai.insurai_backend.model.Dependent;
import com.insurai.insurai_backend.model.Enrollment;
import com.insurai.insurai_backend.service.EnrollmentService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/hr/enrollments")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class HrEnrollmentController {

    private final EnrollmentService enrollmentService;
    private final JwtUtil jwtUtil;

    // ==================== Get All Enrollments ====================
    @GetMapping("/all")
    public ResponseEntity<?> getAllEnrollments(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
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

    // ==================== Get Pending Enrollments ====================
    @GetMapping("/pending")
    public ResponseEntity<?> getPendingEnrollments(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
            }

            List<Enrollment> enrollments = enrollmentService.getAllPendingEnrollments();
            List<EnrollmentDTO> dtos = enrollments.stream()
                    .map(EnrollmentDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching pending enrollments: " + e.getMessage());
        }
    }

    // ==================== Approve Enrollment ====================
    @PostMapping("/{enrollmentId}/approve")
    public ResponseEntity<?> approveEnrollment(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long enrollmentId,
            @RequestBody Map<String, Object> request) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
            }

            String token = authHeader.substring(7).trim();
            String hrEmail = jwtUtil.extractEmail(token);

            String remarks = (String) request.getOrDefault("remarks", "");
            LocalDate effectiveDate = null;
            if (request.containsKey("effectiveDate") && request.get("effectiveDate") != null) {
                effectiveDate = LocalDate.parse((String) request.get("effectiveDate"));
            }

            Enrollment enrollment = enrollmentService.approveEnrollment(
                    enrollmentId, remarks, effectiveDate, hrEmail);

            return ResponseEntity.ok(new EnrollmentDTO(enrollment));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error approving enrollment: " + e.getMessage());
        }
    }

    // ==================== Reject Enrollment ====================
    @PostMapping("/{enrollmentId}/reject")
    public ResponseEntity<?> rejectEnrollment(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long enrollmentId,
            @RequestBody Map<String, String> request) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
            }

            String reason = request.getOrDefault("reason", "No reason provided");

            Enrollment enrollment = enrollmentService.rejectEnrollment(enrollmentId, reason);

            return ResponseEntity.ok(new EnrollmentDTO(enrollment));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error rejecting enrollment: " + e.getMessage());
        }
    }

    // ==================== Get Enrollment Details ====================
    @GetMapping("/{enrollmentId}")
    public ResponseEntity<?> getEnrollmentDetails(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long enrollmentId) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
            }

            Enrollment enrollment = enrollmentService.getEnrollmentById(enrollmentId)
                    .orElse(null);

            if (enrollment == null) {
                return ResponseEntity.notFound().build();
            }

            List<Dependent> dependents = enrollmentService.getDependentsByEnrollment(enrollmentId);

            EnrollmentDetailDTO dto = new EnrollmentDetailDTO(enrollment, dependents);
            return ResponseEntity.ok(dto);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching enrollment: " + e.getMessage());
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

    // ==================== DTOs ====================
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
        public String requestReason;
        public String remarks;

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
            this.requestReason = enrollment.getRequestReason();
            this.remarks = enrollment.getRemarks();
        }
    }

    public static class EnrollmentDetailDTO extends EnrollmentDTO {
        public List<DependentDTO> dependents;

        public EnrollmentDetailDTO(Enrollment enrollment, List<Dependent> deps) {
            super(enrollment);
            this.dependents = deps.stream()
                    .map(DependentDTO::new)
                    .collect(Collectors.toList());
        }
    }

    public static class DependentDTO {
        public Long id;
        public String name;
        public String relationship;
        public LocalDate dateOfBirth;

        public DependentDTO(Dependent dependent) {
            this.id = dependent.getId();
            this.name = dependent.getName();
            this.relationship = dependent.getRelationship();
            this.dateOfBirth = dependent.getDateOfBirth();
        }
    }
}

