package com.insurai.insurai_backend.service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.insurai.insurai_backend.model.Claim;
import com.insurai.insurai_backend.model.Employee;
import com.insurai.insurai_backend.model.Reimbursement;
import com.insurai.insurai_backend.repository.ReimbursementRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ReimbursementService {

    private final ReimbursementRepository reimbursementRepository;
    private final ClaimService claimService;
    private final AuditLogService auditLogService;
    private final InAppNotificationService inAppNotificationService;
    private final NotificationService notificationService;

    /**
     * Initiate reimbursement for an approved claim
     */
    @Transactional
    public Reimbursement initiateReimbursement(Long claimId, String paymentMethod, String remarks,
                                                String hrEmail) throws Exception {
        // Fetch claim
        Claim claim = claimService.getClaimById(claimId);
        if (claim == null) {
            throw new Exception("Claim not found with ID: " + claimId);
        }

        // Validate claim is approved
        if (!"Approved".equalsIgnoreCase(claim.getStatus())) {
            throw new Exception("Only approved claims can be reimbursed. Current status: " + claim.getStatus());
        }

        // Check if reimbursement already exists for this claim
        if (reimbursementRepository.existsByClaim(claim)) {
            throw new Exception("Reimbursement already initiated for this claim");
        }

        // Calculate settlement amount (approved amount minus any deductibles)
        Double settlementAmount = calculateSettlementAmount(claim);

        // Create reimbursement
        Reimbursement reimbursement = new Reimbursement(
                claim,
                claim.getEmployee(),
                claim.getAmount(),
                claim.getAmount(), // approvedAmount
                settlementAmount,
                paymentMethod
        );
        reimbursement.setRemarks(remarks);

        Reimbursement savedReimbursement = reimbursementRepository.save(reimbursement);

        // Audit log
        auditLogService.logAction(
                hrEmail,
                "HR",
                "HR",
                "REIMBURSEMENT_INITIATED",
                "Initiated reimbursement for claim ID: " + claimId + ", Amount: " + settlementAmount
        );

        // Notify employee
        inAppNotificationService.createNotification(
                "Reimbursement Initiated",
                "Reimbursement of ₹" + settlementAmount + " has been initiated for your claim #" + claimId,
                claim.getEmployee().getId(),
                "EMPLOYEE",
                "REIMBURSEMENT"
        );

        // Send email notification
        try {
            notificationService.sendReimbursementStatusEmail(
                    claim.getEmployee().getEmail(),
                    claim.getEmployee().getName(),
                    claimId,
                    "Initiated",
                    settlementAmount
            );
        } catch (Exception e) {
            System.err.println("Failed to send reimbursement initiation email: " + e.getMessage());
        }

        return savedReimbursement;
    }

    /**
     * Process reimbursement (mark as Processing)
     */
    @Transactional
    public Reimbursement processReimbursement(Long reimbursementId, String transactionReferenceId,
                                               LocalDate processedDate, String remarks,
                                               String adminEmail) throws Exception {
        Reimbursement reimbursement = reimbursementRepository.findById(reimbursementId)
                .orElseThrow(() -> new Exception("Reimbursement not found with ID: " + reimbursementId));

        if (!"Pending".equalsIgnoreCase(reimbursement.getStatus())) {
            throw new Exception("Can only process pending reimbursements. Current status: " + reimbursement.getStatus());
        }

        reimbursement.setStatus("Processing");
        reimbursement.setTransactionReferenceId(transactionReferenceId);
        reimbursement.setProcessedDate(processedDate != null ? processedDate : LocalDate.now());
        reimbursement.setProcessedBy(adminEmail);
        reimbursement.setRemarks(remarks);
        reimbursement.setUpdatedAt(LocalDateTime.now());

        Reimbursement savedReimbursement = reimbursementRepository.save(reimbursement);

        // Audit log
        auditLogService.logAction(
                adminEmail,
                "Admin",
                "ADMIN",
                "REIMBURSEMENT_PROCESSING",
                "Processing reimbursement ID: " + reimbursementId + ", Txn Ref: " + transactionReferenceId
        );

        // Notify employee
        inAppNotificationService.createNotification(
                "Payment Processing",
                "Your reimbursement of ₹" + reimbursement.getSettlementAmount() + " is being processed.",
                reimbursement.getEmployee().getId(),
                "EMPLOYEE",
                "REIMBURSEMENT"
        );

        return savedReimbursement;
    }

    /**
     * Complete reimbursement (mark as Completed)
     */
    @Transactional
    public Reimbursement completeReimbursement(Long reimbursementId, LocalDate completedDate,
                                                String remarks, String adminEmail) throws Exception {
        Reimbursement reimbursement = reimbursementRepository.findById(reimbursementId)
                .orElseThrow(() -> new Exception("Reimbursement not found with ID: " + reimbursementId));

        if (!"Processing".equalsIgnoreCase(reimbursement.getStatus())) {
            throw new Exception("Can only complete reimbursements that are being processed. Current status: " + reimbursement.getStatus());
        }

        reimbursement.setStatus("Completed");
        reimbursement.setCompletedDate(completedDate != null ? completedDate : LocalDate.now());
        reimbursement.setRemarks(remarks);
        reimbursement.setUpdatedAt(LocalDateTime.now());

        Reimbursement savedReimbursement = reimbursementRepository.save(reimbursement);

        // Audit log
        auditLogService.logAction(
                adminEmail,
                "Admin",
                "ADMIN",
                "REIMBURSEMENT_COMPLETED",
                "Completed reimbursement ID: " + reimbursementId + ", Amount: ₹" + reimbursement.getSettlementAmount()
        );

        // Notify employee
        inAppNotificationService.createNotification(
                "Payment Completed",
                "Your reimbursement of ₹" + reimbursement.getSettlementAmount() + " has been completed!",
                reimbursement.getEmployee().getId(),
                "EMPLOYEE",
                "REIMBURSEMENT"
        );

        // Send email notification
        try {
            notificationService.sendReimbursementStatusEmail(
                    reimbursement.getEmployee().getEmail(),
                    reimbursement.getEmployee().getName(),
                    reimbursement.getClaim().getId(),
                    "Completed",
                    reimbursement.getSettlementAmount()
            );
        } catch (Exception e) {
            System.err.println("Failed to send reimbursement completion email: " + e.getMessage());
        }

        return savedReimbursement;
    }

    /**
     * Mark reimbursement as failed
     */
    @Transactional
    public Reimbursement failReimbursement(Long reimbursementId, String reason,
                                           String adminEmail) throws Exception {
        Reimbursement reimbursement = reimbursementRepository.findById(reimbursementId)
                .orElseThrow(() -> new Exception("Reimbursement not found with ID: " + reimbursementId));

        reimbursement.setStatus("Failed");
        reimbursement.setRemarks(reason);
        reimbursement.setUpdatedAt(LocalDateTime.now());

        Reimbursement savedReimbursement = reimbursementRepository.save(reimbursement);

        // Audit log
        auditLogService.logAction(
                adminEmail,
                "Admin",
                "ADMIN",
                "REIMBURSEMENT_FAILED",
                "Reimbursement ID: " + reimbursementId + " failed. Reason: " + reason
        );

        // Notify employee
        inAppNotificationService.createNotification(
                "Reimbursement Failed",
                "Your reimbursement could not be processed. Reason: " + reason,
                reimbursement.getEmployee().getId(),
                "EMPLOYEE",
                "REIMBURSEMENT"
        );

        return savedReimbursement;
    }

    /**
     * Get all pending reimbursements
     */
    public List<Reimbursement> getPendingReimbursements() {
        return reimbursementRepository.findByStatus("Pending");
    }

    /**
     * Get reimbursements by employee
     */
    public List<Reimbursement> getReimbursementsByEmployee(Long employeeId) {
        return reimbursementRepository.findByEmployeeId(employeeId);
    }

    /**
     * Get reimbursement by claim ID
     */
    public Optional<Reimbursement> getReimbursementByClaim(Long claimId) {
        return reimbursementRepository.findByClaimId(claimId);
    }

    /**
     * Get all reimbursements
     */
    public List<Reimbursement> getAllReimbursements() {
        return reimbursementRepository.findAll();
    }

    /**
     * Get reimbursement statistics
     */
    public Map<String, Object> getReimbursementStatistics(LocalDate startDate, LocalDate endDate) {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalReimbursements", reimbursementRepository.count());
        stats.put("pendingCount", reimbursementRepository.countByStatus("Pending"));
        stats.put("processingCount", reimbursementRepository.countByStatus("Processing"));
        stats.put("completedCount", reimbursementRepository.countByStatus("Completed"));
        stats.put("failedCount", reimbursementRepository.countByStatus("Failed"));

        if (startDate != null && endDate != null) {
            Double totalDisbursed = reimbursementRepository.sumTotalAmountByStatusAndDateRange(
                    "Completed", startDate, endDate);
            stats.put("totalDisbursedInRange", totalDisbursed != null ? totalDisbursed : 0.0);
        }

        return stats;
    }

    /**
     * Get reimbursement by ID
     */
    public Optional<Reimbursement> getReimbursementById(Long reimbursementId) {
        return reimbursementRepository.findById(reimbursementId);
    }

    // -------------------- Helper Methods --------------------

    private Double calculateSettlementAmount(Claim claim) {
        // For now, settlement = approved amount
        // In future, can apply deductibles, co-pay, etc.
        return claim.getAmount();
    }
}

