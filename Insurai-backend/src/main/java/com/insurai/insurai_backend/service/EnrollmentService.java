package com.insurai.insurai_backend.service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.insurai.insurai_backend.model.Dependent;
import com.insurai.insurai_backend.model.Employee;
import com.insurai.insurai_backend.model.Enrollment;
import com.insurai.insurai_backend.model.Hr;
import com.insurai.insurai_backend.model.Policy;
import com.insurai.insurai_backend.repository.DependentRepository;
import com.insurai.insurai_backend.repository.EnrollmentRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EnrollmentService {

    private final EnrollmentRepository enrollmentRepository;
    private final DependentRepository dependentRepository;
    private final HrService hrService;
    private final PolicyService policyService;
    private final AuditLogService auditLogService;
    private final InAppNotificationService inAppNotificationService;
    private final NotificationService notificationService;

    /**
     * Create a new enrollment request
     */
    @Transactional
    public Enrollment createEnrollment(Employee employee, Long policyId, String coverageType,
                                        String requestReason, List<Map<String, Object>> dependents) throws Exception {
        // Fetch policy
        Policy policy = policyService.getPolicyById(policyId)
                .orElseThrow(() -> new Exception("Policy not found with ID: " + policyId));

        // Validate policy is active
        if (!"Active".equalsIgnoreCase(policy.getPolicyStatus())) {
            throw new Exception("Policy is not available for enrollment. Status: " + policy.getPolicyStatus());
        }

        // Check if employee is already enrolled in this policy
        Optional<Enrollment> existingEnrollment = enrollmentRepository.findByEmployeeAndPolicyAndStatusNot(
                employee, policy, "Rejected");
        if (existingEnrollment.isPresent()) {
            throw new Exception("Employee is already enrolled or has a pending enrollment for this policy");
        }

        // Calculate premium based on coverage type
        Double premiumAmount = calculatePremium(policy, coverageType);

        // Create enrollment
        Enrollment enrollment = new Enrollment(employee, policy, coverageType, premiumAmount, requestReason);

        // Assign HR for approval (load-balanced)
        Hr assignedHr = assignHrForApproval();
        enrollment.setAssignedHr(assignedHr);

        // Save enrollment
        Enrollment savedEnrollment = enrollmentRepository.save(enrollment);

        // Add dependents if Family or Family_Floater coverage
        String normalizedCoverage = coverageType.toUpperCase();
        if ((normalizedCoverage.equals("FAMILY") || normalizedCoverage.equals("FAMILY_FLOATER"))
                && dependents != null && !dependents.isEmpty()) {
            for (Map<String, Object> depData : dependents) {
                Dependent dependent = new Dependent(
                        savedEnrollment,
                        (String) depData.get("name"),
                        (String) depData.get("relationship"),
                        LocalDate.parse((String) depData.get("dateOfBirth")),
                        (String) depData.getOrDefault("dependentId", null)
                );
                dependentRepository.save(dependent);
            }
        }

        // Audit log
        auditLogService.logAction(
                employee.getId().toString(),
                employee.getName(),
                "EMPLOYEE",
                "ENROLLMENT_REQUEST",
                "Requested enrollment for policy: " + policy.getPolicyName()
        );

        // In-app notification to employee
        inAppNotificationService.createNotification(
                "Enrollment Submitted",
                "Your enrollment request for " + policy.getPolicyName() + " has been submitted for review.",
                employee.getId(),
                "EMPLOYEE",
                "ENROLLMENT"
        );

        // Notify assigned HR
        if (assignedHr != null) {
            inAppNotificationService.createNotification(
                    "New Enrollment Request",
                    "New enrollment request from " + employee.getName() + " for " + policy.getPolicyName(),
                    assignedHr.getId(),
                    "HR",
                    "ENROLLMENT"
            );
        }

        return savedEnrollment;
    }

    /**
     * Approve an enrollment
     */
    @Transactional
    public Enrollment approveEnrollment(Long enrollmentId, String remarks, LocalDate effectiveDate,
                                        String hrEmail) throws Exception {
        Enrollment enrollment = enrollmentRepository.findById(enrollmentId)
                .orElseThrow(() -> new Exception("Enrollment not found with ID: " + enrollmentId));

        if (!"Pending".equalsIgnoreCase(enrollment.getStatus())) {
            throw new Exception("Cannot approve enrollment. Current status: " + enrollment.getStatus());
        }

        enrollment.setStatus("Approved");
        enrollment.setRemarks(remarks);
        enrollment.setEffectiveDate(effectiveDate != null ? effectiveDate : LocalDate.now());
        enrollment.setUpdatedAt(LocalDateTime.now());

        Enrollment savedEnrollment = enrollmentRepository.save(enrollment);

        // Audit log
        auditLogService.logAction(
                enrollment.getAssignedHr() != null ? enrollment.getAssignedHr().getId().toString() : "HR",
                enrollment.getAssignedHr() != null ? enrollment.getAssignedHr().getName() : "HR",
                "HR",
                "ENROLLMENT_APPROVED",
                "Approved enrollment ID: " + enrollmentId + " for policy: " + enrollment.getPolicy().getPolicyName()
        );

        // Notify employee
        inAppNotificationService.createNotification(
                "Enrollment Approved",
                "Your enrollment for " + enrollment.getPolicy().getPolicyName() + " has been approved!",
                enrollment.getEmployee().getId(),
                "EMPLOYEE",
                "ENROLLMENT"
        );

        // Send email notification
        try {
            notificationService.sendEnrollmentApprovalEmail(
                    enrollment.getEmployee().getEmail(),
                    enrollment.getEmployee().getName(),
                    enrollment.getPolicy().getPolicyName(),
                    effectiveDate
            );
        } catch (Exception e) {
            System.err.println("Failed to send enrollment approval email: " + e.getMessage());
        }

        return savedEnrollment;
    }

    /**
     * Reject an enrollment
     */
    @Transactional
    public Enrollment rejectEnrollment(Long enrollmentId, String reason) throws Exception {
        Enrollment enrollment = enrollmentRepository.findById(enrollmentId)
                .orElseThrow(() -> new Exception("Enrollment not found with ID: " + enrollmentId));

        if (!"Pending".equalsIgnoreCase(enrollment.getStatus())) {
            throw new Exception("Cannot reject enrollment. Current status: " + enrollment.getStatus());
        }

        enrollment.setStatus("Rejected");
        enrollment.setRemarks(reason);
        enrollment.setUpdatedAt(LocalDateTime.now());

        Enrollment savedEnrollment = enrollmentRepository.save(enrollment);

        // Audit log
        auditLogService.logAction(
                enrollment.getAssignedHr() != null ? enrollment.getAssignedHr().getId().toString() : "HR",
                enrollment.getAssignedHr() != null ? enrollment.getAssignedHr().getName() : "HR",
                "HR",
                "ENROLLMENT_REJECTED",
                "Rejected enrollment ID: " + enrollmentId + ". Reason: " + reason
        );

        // Notify employee
        inAppNotificationService.createNotification(
                "Enrollment Rejected",
                "Your enrollment for " + enrollment.getPolicy().getPolicyName() + " was rejected. Reason: " + reason,
                enrollment.getEmployee().getId(),
                "EMPLOYEE",
                "ENROLLMENT"
        );

        return savedEnrollment;
    }

    /**
     * Add dependents to an existing enrollment
     */
    @Transactional
    public List<Dependent> addDependents(Long enrollmentId, List<Map<String, Object>> dependents,
                                         Long employeeId) throws Exception {
        Enrollment enrollment = enrollmentRepository.findById(enrollmentId)
                .orElseThrow(() -> new Exception("Enrollment not found with ID: " + enrollmentId));

        // Verify employee owns this enrollment
        if (!enrollment.getEmployee().getId().equals(employeeId)) {
            throw new Exception("Unauthorized: You can only add dependents to your own enrollment");
        }

        // Verify enrollment is approved/active
        if (!enrollment.getStatus().equalsIgnoreCase("Approved") &&
            !enrollment.getStatus().equalsIgnoreCase("Active")) {
            throw new Exception("Can only add dependents to approved or active enrollments");
        }

        for (Map<String, Object> depData : dependents) {
            Dependent dependent = new Dependent(
                    enrollment,
                    (String) depData.get("name"),
                    (String) depData.get("relationship"),
                    LocalDate.parse((String) depData.get("dateOfBirth")),
                    (String) depData.getOrDefault("dependentId", null)
            );
            dependentRepository.save(dependent);
        }

        // Audit log
        auditLogService.logAction(
                employeeId.toString(),
                enrollment.getEmployee().getName(),
                "EMPLOYEE",
                "DEPENDENTS_ADDED",
                "Added " + dependents.size() + " dependent(s) to enrollment ID: " + enrollmentId
        );

        return dependentRepository.findByEnrollment(enrollment);
    }

    /**
     * Get enrollments by employee
     */
    public List<Enrollment> getEnrollmentsByEmployee(Long employeeId) {
        return enrollmentRepository.findByEmployeeId(employeeId);
    }

    /**
     * Get pending enrollments for HR
     */
    public List<Enrollment> getPendingEnrollmentsForHr(Long hrId) {
        Hr hr = new Hr();
        hr.setId(hrId);
        return enrollmentRepository.findByAssignedHrAndStatus(hr, "Pending");
    }

    /**
     * Get all pending enrollments
     */
    public List<Enrollment> getAllPendingEnrollments() {
        return enrollmentRepository.findByStatus("Pending");
    }

    /**
     * Get all enrollments
     */
    public List<Enrollment> getAllEnrollments() {
        return enrollmentRepository.findAll();
    }

    /**
     * Get enrollment statistics
     */
    public Map<String, Object> getEnrollmentStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalEnrollments", enrollmentRepository.count());
        stats.put("pendingCount", enrollmentRepository.countByStatus("Pending"));
        stats.put("approvedCount", enrollmentRepository.countByStatus("Approved"));
        stats.put("rejectedCount", enrollmentRepository.countByStatus("Rejected"));
        stats.put("activeCount", enrollmentRepository.countByStatus("Active"));
        return stats;
    }

    /**
     * Get dependents for an enrollment
     */
    public List<Dependent> getDependentsByEnrollment(Long enrollmentId) {
        return dependentRepository.findByEnrollmentId(enrollmentId);
    }

    /**
     * Get enrollment by ID
     */
    public Optional<Enrollment> getEnrollmentById(Long enrollmentId) {
        return enrollmentRepository.findById(enrollmentId);
    }

    // -------------------- Helper Methods --------------------

    private Double calculatePremium(Policy policy, String coverageType) {
        Double basePremium = policy.getMonthlyPremium();
        if ("Family".equalsIgnoreCase(coverageType)) {
            return basePremium * 2.5; // Family premium is 2.5x individual
        }
        return basePremium;
    }

    private Hr assignHrForApproval() {
        List<Hr> activeHrs = hrService.getAllActiveHrs();
        if (activeHrs.isEmpty()) {
            return null;
        }
        // Load-balanced assignment: assign to HR with least pending enrollments
        return activeHrs.stream()
                .min(Comparator.comparingInt(hr ->
                        enrollmentRepository.findByAssignedHrAndStatus(hr, "Pending").size()))
                .orElse(activeHrs.get(0));
    }
}

