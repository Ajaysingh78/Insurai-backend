package com.insurai.insurai_backend.service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.insurai.insurai_backend.model.Enrollment;
import com.insurai.insurai_backend.model.Policy;
import com.insurai.insurai_backend.model.RenewalConfig;
import com.insurai.insurai_backend.model.RenewalHistory;
import com.insurai.insurai_backend.repository.EnrollmentRepository;
import com.insurai.insurai_backend.repository.PolicyRepository;
import com.insurai.insurai_backend.repository.RenewalConfigRepository;
import com.insurai.insurai_backend.repository.RenewalHistoryRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class RenewalService {

    private final PolicyRepository policyRepository;
    private final RenewalConfigRepository renewalConfigRepository;
    private final RenewalHistoryRepository renewalHistoryRepository;
    private final EnrollmentRepository enrollmentRepository;
    private final AuditLogService auditLogService;
    private final InAppNotificationService inAppNotificationService;
    private final NotificationService notificationService;

    // -------------------- Configuration Methods --------------------

    /**
     * Get current renewal configuration
     */
    public RenewalConfig getRenewalConfiguration() {
        return renewalConfigRepository.findTopByOrderByIdDesc()
                .orElseGet(this::createDefaultConfig);
    }

    /**
     * Update renewal configuration
     */
    @Transactional
    public RenewalConfig updateRenewalConfiguration(Boolean alertsEnabled, Integer firstAlertDays,
                                                    Integer secondAlertDays, Integer finalAlertDays,
                                                    Boolean autoExpireEnabled, String adminEmail) {
        RenewalConfig config = getRenewalConfiguration();

        if (alertsEnabled != null) config.setAlertsEnabled(alertsEnabled);
        if (firstAlertDays != null) config.setFirstAlertDays(firstAlertDays);
        if (secondAlertDays != null) config.setSecondAlertDays(secondAlertDays);
        if (finalAlertDays != null) config.setFinalAlertDays(finalAlertDays);
        if (autoExpireEnabled != null) config.setAutoExpireEnabled(autoExpireEnabled);

        config.setLastModifiedAt(LocalDateTime.now());
        config.setLastModifiedBy(adminEmail);

        RenewalConfig savedConfig = renewalConfigRepository.save(config);

        // Audit log
        auditLogService.logAction(
                adminEmail,
                "Admin",
                "ADMIN",
                "RENEWAL_CONFIG_UPDATED",
                "Updated renewal configuration: alerts=" + alertsEnabled + ", autoExpire=" + autoExpireEnabled
        );

        return savedConfig;
    }

    // -------------------- Renewal Alert Methods --------------------

    /**
     * Daily scheduled job for renewal alerts (runs at 2:00 AM)
     */
    @Scheduled(cron = "0 0 2 * * ?")
    @Transactional
    public void dailyRenewalCheck() {
        log.info("Starting daily renewal check job...");

        RenewalConfig config = getRenewalConfiguration();

        if (!config.getAlertsEnabled()) {
            log.info("Renewal alerts are disabled. Skipping...");
            return;
        }

        int totalAlertsSent = 0;
        LocalDate today = LocalDate.now();

        // First alert (e.g., 30 days before)
        totalAlertsSent += sendRenewalAlerts(
                config.getFirstAlertDays(),
                "First reminder: Your policy will expire in " + config.getFirstAlertDays() + " days"
        );

        // Second alert (e.g., 15 days before)
        totalAlertsSent += sendRenewalAlerts(
                config.getSecondAlertDays(),
                "Second reminder: Your policy will expire in " + config.getSecondAlertDays() + " days"
        );

        // Final alert (e.g., 7 days before)
        totalAlertsSent += sendRenewalAlerts(
                config.getFinalAlertDays(),
                "URGENT: Your policy will expire in " + config.getFinalAlertDays() + " days!"
        );

        // Audit log
        auditLogService.logAction(
                "SYSTEM",
                "Scheduled Job",
                "SYSTEM",
                "RENEWAL_ALERTS_SENT",
                "Daily renewal check completed. Total alerts sent: " + totalAlertsSent
        );

        log.info("Daily renewal check completed. Total alerts sent: {}", totalAlertsSent);
    }

    /**
     * Auto-expire policies past renewal date (runs at 3:00 AM)
     */
    @Scheduled(cron = "0 0 3 * * ?")
    @Transactional
    public void autoExpirePolicies() {
        log.info("Starting auto-expire policies job...");

        RenewalConfig config = getRenewalConfiguration();

        if (!config.getAutoExpireEnabled()) {
            log.info("Auto-expiry is disabled. Skipping...");
            return;
        }

        LocalDate today = LocalDate.now();
        List<Policy> expiredPolicies = policyRepository.findExpiredActivePolicies(today);

        int expiredCount = 0;
        for (Policy policy : expiredPolicies) {
            expirePolicy(policy);
            expiredCount++;
        }

        // Audit log
        auditLogService.logAction(
                "SYSTEM",
                "Scheduled Job",
                "SYSTEM",
                "AUTO_EXPIRE_POLICIES",
                "Auto-expiry job completed. Policies expired: " + expiredCount
        );

        log.info("Auto-expiry job completed. Policies expired: {}", expiredCount);
    }

    /**
     * Manual trigger for renewal check (Admin only)
     */
    @Transactional
    public Map<String, Object> executeRenewalJobManually(String adminEmail) {
        Map<String, Object> result = new HashMap<>();

        RenewalConfig config = getRenewalConfiguration();
        int totalAlertsSent = 0;

        if (config.getAlertsEnabled()) {
            totalAlertsSent += sendRenewalAlerts(config.getFirstAlertDays(),
                    "Reminder: Your policy will expire in " + config.getFirstAlertDays() + " days");
            totalAlertsSent += sendRenewalAlerts(config.getSecondAlertDays(),
                    "Reminder: Your policy will expire in " + config.getSecondAlertDays() + " days");
            totalAlertsSent += sendRenewalAlerts(config.getFinalAlertDays(),
                    "URGENT: Your policy will expire in " + config.getFinalAlertDays() + " days!");
        }

        int expiredCount = 0;
        if (config.getAutoExpireEnabled()) {
            List<Policy> expiredPolicies = policyRepository.findExpiredActivePolicies(LocalDate.now());
            for (Policy policy : expiredPolicies) {
                expirePolicy(policy);
                expiredCount++;
            }
        }

        result.put("alertsSent", totalAlertsSent);
        result.put("policiesExpired", expiredCount);
        result.put("executedAt", LocalDateTime.now());
        result.put("executedBy", adminEmail);

        // Audit log
        auditLogService.logAction(
                adminEmail,
                "Admin",
                "ADMIN",
                "MANUAL_RENEWAL_JOB",
                "Manually triggered renewal job. Alerts: " + totalAlertsSent + ", Expired: " + expiredCount
        );

        return result;
    }

    // -------------------- Policy Renewal Methods --------------------

    /**
     * Renew a policy manually
     */
    @Transactional
    public Policy renewPolicy(Long policyId, LocalDate newRenewalDate, String renewedBy) throws Exception {
        Policy policy = policyRepository.findById(policyId)
                .orElseThrow(() -> new Exception("Policy not found with ID: " + policyId));

        LocalDate oldRenewalDate = policy.getRenewalDate();

        // Create renewal history
        RenewalHistory history = new RenewalHistory(
                policy,
                oldRenewalDate,
                newRenewalDate,
                renewedBy,
                "Manual"
        );
        renewalHistoryRepository.save(history);

        // Update policy
        policy.setRenewalDate(newRenewalDate);
        policy.setPolicyStatus("Active");
        Policy savedPolicy = policyRepository.save(policy);

        // Audit log
        auditLogService.logAction(
                renewedBy,
                "Admin/HR",
                "ADMIN",
                "POLICY_RENEWED",
                "Renewed policy: " + policy.getPolicyName() + " until " + newRenewalDate
        );

        // Notify enrolled employees
        notifyEnrolledEmployees(policy, "Policy Renewed",
                "Your policy " + policy.getPolicyName() + " has been renewed until " + newRenewalDate);

        return savedPolicy;
    }

    /**
     * Get policies expiring in specified days
     */
    public List<Policy> getPoliciesExpiringInDays(int days) {
        LocalDate today = LocalDate.now();
        LocalDate targetDate = today.plusDays(days);
        return policyRepository.findPoliciesExpiringBetween(today, targetDate);
    }

    /**
     * Get upcoming renewals
     */
    public List<Policy> getUpcomingRenewals(int daysAhead) {
        LocalDate today = LocalDate.now();
        LocalDate futureDate = today.plusDays(daysAhead);
        return policyRepository.findByRenewalDateBetween(today, futureDate);
    }

    /**
     * Get renewal history for a policy
     */
    public List<RenewalHistory> getRenewalHistory(Long policyId) {
        return renewalHistoryRepository.findByPolicyIdOrderByRenewedAtDesc(policyId);
    }

    // -------------------- Helper Methods --------------------

    // -------------------- Statistics Methods --------------------

    /**
     * Get renewal statistics for admin dashboard
     */
    public Map<String, Object> getRenewalStatistics() {
        Map<String, Object> stats = new HashMap<>();
        LocalDate today = LocalDate.now();

        // Total active policies
        long totalPolicies = policyRepository.countByPolicyStatus("Active");
        stats.put("totalPolicies", totalPolicies);

        // Policies expiring in next 7 days
        long next7Days = policyRepository.countByRenewalDateBetweenAndPolicyStatus(
                today, today.plusDays(7), "Active");

        // Policies expiring in next 15 days
        long next15Days = policyRepository.countByRenewalDateBetweenAndPolicyStatus(
                today, today.plusDays(15), "Active");

        // Policies expiring in next 30 days
        long next30Days = policyRepository.countByRenewalDateBetweenAndPolicyStatus(
                today, today.plusDays(30), "Active");

        // Expired policies
        long expired = policyRepository.countByPolicyStatus("Expired");
        stats.put("expired", expired);

        stats.put("expiringSoon", next30Days);

        Map<String, Long> byTimeframe = new HashMap<>();
        byTimeframe.put("next7Days", next7Days);
        byTimeframe.put("next15Days", next15Days);
        byTimeframe.put("next30Days", next30Days);
        stats.put("byTimeframe", byTimeframe);

        // Alerts sent today (placeholder - can be implemented with audit logs)
        stats.put("alertsSentToday", 0);

        return stats;
    }

    // -------------------- Helper Methods --------------------

    private RenewalConfig createDefaultConfig() {
        RenewalConfig config = new RenewalConfig();
        config.setAlertsEnabled(true);
        config.setFirstAlertDays(30);
        config.setSecondAlertDays(15);
        config.setFinalAlertDays(7);
        config.setAutoExpireEnabled(true);
        config.setLastModifiedAt(LocalDateTime.now());
        config.setLastModifiedBy("SYSTEM");
        return renewalConfigRepository.save(config);
    }

    private int sendRenewalAlerts(int daysBeforeExpiry, String alertMessage) {
        LocalDate today = LocalDate.now();
        LocalDate targetDate = today.plusDays(daysBeforeExpiry);

        // Find policies expiring on this exact date
        List<Policy> policies = policyRepository.findByRenewalDateBetween(targetDate, targetDate);

        int alertCount = 0;
        for (Policy policy : policies) {
            // Notify enrolled employees
            List<Enrollment> enrollments = enrollmentRepository.findActiveEnrollmentsByPolicyId(policy.getId());

            for (Enrollment enrollment : enrollments) {
                // In-app notification
                inAppNotificationService.createNotification(
                        "Policy Renewal Alert",
                        alertMessage + " - " + policy.getPolicyName(),
                        enrollment.getEmployee().getId(),
                        "EMPLOYEE",
                        "RENEWAL"
                );

                // Email notification
                try {
                    notificationService.sendRenewalAlertEmail(
                            enrollment.getEmployee().getEmail(),
                            enrollment.getEmployee().getName(),
                            policy.getPolicyName(),
                            policy.getRenewalDate(),
                            daysBeforeExpiry
                    );
                } catch (Exception e) {
                    log.error("Failed to send renewal alert email: {}", e.getMessage());
                }

                alertCount++;
            }

            // Also notify HR and Admin
            inAppNotificationService.createNotificationForRole(
                    "Policy Expiring Soon",
                    policy.getPolicyName() + " expires in " + daysBeforeExpiry + " days",
                    "HR",
                    "RENEWAL"
            );

            inAppNotificationService.createNotificationForRole(
                    "Policy Expiring Soon",
                    policy.getPolicyName() + " expires in " + daysBeforeExpiry + " days",
                    "ADMIN",
                    "RENEWAL"
            );
        }

        return alertCount;
    }

    private void expirePolicy(Policy policy) {
        LocalDate oldRenewalDate = policy.getRenewalDate();

        // Create renewal history entry for expiry
        RenewalHistory history = new RenewalHistory(
                policy,
                oldRenewalDate,
                oldRenewalDate, // same date
                "SYSTEM",
                "Expiry"
        );
        renewalHistoryRepository.save(history);

        // Update policy status
        policy.setPolicyStatus("Expired");
        policyRepository.save(policy);

        // Notify enrolled employees
        notifyEnrolledEmployees(policy, "Policy Expired",
                "Your policy " + policy.getPolicyName() + " has expired. Please contact HR for renewal options.");

        log.info("Policy expired: {} (ID: {})", policy.getPolicyName(), policy.getId());
    }

    private void notifyEnrolledEmployees(Policy policy, String title, String message) {
        List<Enrollment> enrollments = enrollmentRepository.findActiveEnrollmentsByPolicyId(policy.getId());

        for (Enrollment enrollment : enrollments) {
            inAppNotificationService.createNotification(
                    title,
                    message,
                    enrollment.getEmployee().getId(),
                    "EMPLOYEE",
                    "RENEWAL"
            );

            try {
                notificationService.sendPolicyStatusEmail(
                        enrollment.getEmployee().getEmail(),
                        enrollment.getEmployee().getName(),
                        policy.getPolicyName(),
                        policy.getPolicyStatus()
                );
            } catch (Exception e) {
                log.error("Failed to send policy status email: {}", e.getMessage());
            }
        }
    }
}

