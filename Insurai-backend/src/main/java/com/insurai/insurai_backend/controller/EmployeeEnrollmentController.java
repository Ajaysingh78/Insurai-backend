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
import com.insurai.insurai_backend.model.Employee;
import com.insurai.insurai_backend.model.Enrollment;
import com.insurai.insurai_backend.repository.EmployeeRepository;
import com.insurai.insurai_backend.service.EnrollmentService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/employee/enrollments")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class EmployeeEnrollmentController {

    private final EnrollmentService enrollmentService;
    private final EmployeeRepository employeeRepository;
    private final JwtUtil jwtUtil;

    // ==================== Submit Enrollment Request ====================
    @PostMapping("/request")
    public ResponseEntity<?> submitEnrollment(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody Map<String, Object> request) {
        try {
            // Validate JWT
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

            // Extract request data
            Long policyId = Long.valueOf(request.get("policyId").toString());
            String coverageType = (String) request.get("coverageType");
            String requestReason = (String) request.getOrDefault("requestReason", "");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> dependents = (List<Map<String, Object>>) request.get("dependents");

            // Validate coverage type
            String normalizedCoverageType = coverageType.toUpperCase();
            if (!normalizedCoverageType.equals("INDIVIDUAL") &&
                !normalizedCoverageType.equals("FAMILY") &&
                !normalizedCoverageType.equals("FAMILY_FLOATER")) {
                return ResponseEntity.badRequest().body("Coverage type must be 'Individual', 'Family', or 'Family_Floater'");
            }

            Enrollment enrollment = enrollmentService.createEnrollment(
                    employee, policyId, coverageType, requestReason, dependents);

            return ResponseEntity.ok(new EnrollmentDTO(enrollment));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error submitting enrollment: " + e.getMessage());
        }
    }

    // ==================== Get My Enrollments ====================
    @GetMapping("/my")
    public ResponseEntity<?> getMyEnrollments(
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

            List<Enrollment> enrollments = enrollmentService.getEnrollmentsByEmployee(employee.getId());
            List<EnrollmentDTO> dtos = enrollments.stream()
                    .map(EnrollmentDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching enrollments: " + e.getMessage());
        }
    }

    // ==================== Add Dependents to Enrollment ====================
    @PostMapping("/{enrollmentId}/dependents")
    public ResponseEntity<?> addDependents(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long enrollmentId,
            @RequestBody Map<String, Object> request) {
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

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> dependents = (List<Map<String, Object>>) request.get("dependents");

            if (dependents == null || dependents.isEmpty()) {
                return ResponseEntity.badRequest().body("Dependents list cannot be empty");
            }

            List<Dependent> savedDependents = enrollmentService.addDependents(
                    enrollmentId, dependents, employee.getId());

            List<DependentDTO> dtos = savedDependents.stream()
                    .map(DependentDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error adding dependents: " + e.getMessage());
        }
    }

    // ==================== Get Dependents for Enrollment ====================
    @GetMapping("/{enrollmentId}/dependents")
    public ResponseEntity<?> getDependents(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long enrollmentId) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(403).body("Missing or invalid Authorization header");
            }

            String token = authHeader.substring(7).trim();
            String role = jwtUtil.extractRole(token);

            if (!"EMPLOYEE".equalsIgnoreCase(role)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an employee");
            }

            List<Dependent> dependents = enrollmentService.getDependentsByEnrollment(enrollmentId);
            List<DependentDTO> dtos = dependents.stream()
                    .map(DependentDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching dependents: " + e.getMessage());
        }
    }

    // ==================== DTOs ====================
    public static class EnrollmentDTO {
        public Long id;
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
        public String assignedHrName;

        public EnrollmentDTO(Enrollment enrollment) {
            this.id = enrollment.getId();
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
            this.assignedHrName = enrollment.getAssignedHr() != null ? enrollment.getAssignedHr().getName() : null;
        }
    }

    public static class DependentDTO {
        public Long id;
        public String name;
        public String relationship;
        public LocalDate dateOfBirth;
        public String dependentId;

        public DependentDTO(Dependent dependent) {
            this.id = dependent.getId();
            this.name = dependent.getName();
            this.relationship = dependent.getRelationship();
            this.dateOfBirth = dependent.getDateOfBirth();
            this.dependentId = dependent.getDependentId();
        }
    }
}

