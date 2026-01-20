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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.insurai.insurai_backend.config.JwtUtil;
import com.insurai.insurai_backend.model.Employee;
import com.insurai.insurai_backend.model.Reimbursement;
import com.insurai.insurai_backend.repository.EmployeeRepository;
import com.insurai.insurai_backend.service.ReimbursementService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class ReimbursementController {

    private final ReimbursementService reimbursementService;
    private final EmployeeRepository employeeRepository;
    private final JwtUtil jwtUtil;

    // ==================== HR: Initiate Reimbursement ====================
    @PostMapping("/hr/claims/{claimId}/initiate-reimbursement")
    public ResponseEntity<?> initiateReimbursement(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long claimId,
            @RequestBody Map<String, String> request) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
            }

            String token = authHeader.substring(7).trim();
            String hrEmail = jwtUtil.extractEmail(token);

            String paymentMethod = request.getOrDefault("paymentMethod", "Bank Transfer");
            String remarks = request.getOrDefault("remarks", "");

            Reimbursement reimbursement = reimbursementService.initiateReimbursement(
                    claimId, paymentMethod, remarks, hrEmail);

            return ResponseEntity.ok(new ReimbursementDTO(reimbursement));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error initiating reimbursement: " + e.getMessage());
        }
    }

    // ==================== HR: Get Pending Reimbursements ====================
    @GetMapping("/hr/reimbursements/pending")
    public ResponseEntity<?> getHrPendingReimbursements(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
            }

            List<Reimbursement> reimbursements = reimbursementService.getPendingReimbursements();
            List<ReimbursementDTO> dtos = reimbursements.stream()
                    .map(ReimbursementDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching pending reimbursements: " + e.getMessage());
        }
    }

    // ==================== HR: Get Reimbursement History ====================
    @GetMapping("/hr/reimbursements/history")
    public ResponseEntity<?> getHrReimbursementHistory(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateHrToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an HR");
            }

            List<Reimbursement> reimbursements = reimbursementService.getAllReimbursements();
            List<ReimbursementDTO> dtos = reimbursements.stream()
                    .map(ReimbursementDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching reimbursement history: " + e.getMessage());
        }
    }

    // ==================== Admin: Get Pending Reimbursements ====================
    @GetMapping("/admin/reimbursements/pending")
    public ResponseEntity<?> getPendingReimbursements(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            List<Reimbursement> reimbursements = reimbursementService.getPendingReimbursements();
            List<ReimbursementDTO> dtos = reimbursements.stream()
                    .map(ReimbursementDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching pending reimbursements: " + e.getMessage());
        }
    }

    // ==================== Admin: Get All Reimbursements ====================
    @GetMapping("/admin/reimbursements/all")
    public ResponseEntity<?> getAllReimbursements(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            List<Reimbursement> reimbursements = reimbursementService.getAllReimbursements();
            List<ReimbursementDTO> dtos = reimbursements.stream()
                    .map(ReimbursementDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching reimbursements: " + e.getMessage());
        }
    }

    // ==================== Admin: Process Reimbursement ====================
    @PostMapping("/admin/reimbursements/{id}/process")
    public ResponseEntity<?> processReimbursement(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody Map<String, Object> request) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            String token = authHeader.substring(7).trim();
            String adminEmail = jwtUtil.extractEmail(token);

            String transactionReferenceId = (String) request.get("transactionReferenceId");
            LocalDate processedDate = null;
            if (request.containsKey("processedDate") && request.get("processedDate") != null) {
                processedDate = LocalDate.parse((String) request.get("processedDate"));
            }
            String remarks = (String) request.getOrDefault("remarks", "");

            Reimbursement reimbursement = reimbursementService.processReimbursement(
                    id, transactionReferenceId, processedDate, remarks, adminEmail);

            return ResponseEntity.ok(new ReimbursementDTO(reimbursement));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error processing reimbursement: " + e.getMessage());
        }
    }

    // ==================== Admin: Complete Reimbursement ====================
    @PostMapping("/admin/reimbursements/{id}/complete")
    public ResponseEntity<?> completeReimbursement(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody Map<String, Object> request) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            String token = authHeader.substring(7).trim();
            String adminEmail = jwtUtil.extractEmail(token);

            LocalDate completedDate = null;
            if (request.containsKey("completedDate") && request.get("completedDate") != null) {
                completedDate = LocalDate.parse((String) request.get("completedDate"));
            }
            String remarks = (String) request.getOrDefault("remarks", "");

            Reimbursement reimbursement = reimbursementService.completeReimbursement(
                    id, completedDate, remarks, adminEmail);

            return ResponseEntity.ok(new ReimbursementDTO(reimbursement));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error completing reimbursement: " + e.getMessage());
        }
    }

    // ==================== Admin: Reimbursement Statistics ====================
    @GetMapping("/admin/reimbursements/stats")
    public ResponseEntity<?> getReimbursementStatistics(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam(required = false) String startDate,
            @RequestParam(required = false) String endDate) {
        try {
            if (!validateAdminToken(authHeader)) {
                return ResponseEntity.status(403).body("Unauthorized: Not an Admin");
            }

            LocalDate start = startDate != null ? LocalDate.parse(startDate) : null;
            LocalDate end = endDate != null ? LocalDate.parse(endDate) : null;

            Map<String, Object> stats = reimbursementService.getReimbursementStatistics(start, end);
            return ResponseEntity.ok(stats);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching statistics: " + e.getMessage());
        }
    }

    // ==================== Employee: Get My Reimbursements ====================
    @GetMapping("/employee/reimbursements/my")
    public ResponseEntity<?> getMyReimbursements(
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

            List<Reimbursement> reimbursements = reimbursementService.getReimbursementsByEmployee(employee.getId());
            List<ReimbursementDTO> dtos = reimbursements.stream()
                    .map(ReimbursementDTO::new)
                    .collect(Collectors.toList());

            return ResponseEntity.ok(dtos);

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching reimbursements: " + e.getMessage());
        }
    }

    // ==================== Employee: Get Reimbursement Details ====================
    @GetMapping("/employee/reimbursements/{id}")
    public ResponseEntity<?> getReimbursementDetails(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
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

            Reimbursement reimbursement = reimbursementService.getReimbursementById(id).orElse(null);
            if (reimbursement == null) {
                return ResponseEntity.status(404).body("Reimbursement not found");
            }

            // Verify employee owns this reimbursement
            if (!reimbursement.getEmployee().getId().equals(employee.getId())) {
                return ResponseEntity.status(403).body("Unauthorized: Cannot access this reimbursement");
            }

            return ResponseEntity.ok(new ReimbursementDTO(reimbursement));

        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching reimbursement: " + e.getMessage());
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

    private boolean validateAdminToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return false;
        }
        String token = authHeader.substring(7).trim();
        String role = jwtUtil.extractRole(token);
        return "ADMIN".equalsIgnoreCase(role);
    }

    // ==================== DTO ====================
    public static class ReimbursementDTO {
        public Long id;
        public Long claimId;
        public String claimTitle;
        public Long employeeId;
        public String employeeName;
        public String status;
        public Double claimAmount;
        public Double approvedAmount;
        public Double deductibleAmount;
        public Double settlementAmount;
        public String paymentMethod;
        public String transactionReferenceId;
        public LocalDate initiatedDate;
        public LocalDate processedDate;
        public LocalDate completedDate;
        public String processedBy;
        public String remarks;

        public ReimbursementDTO(Reimbursement r) {
            this.id = r.getId();
            this.claimId = r.getClaim() != null ? r.getClaim().getId() : null;
            this.claimTitle = r.getClaim() != null ? r.getClaim().getTitle() : null;
            this.employeeId = r.getEmployee() != null ? r.getEmployee().getId() : null;
            this.employeeName = r.getEmployee() != null ? r.getEmployee().getName() : null;
            this.status = r.getStatus();
            this.claimAmount = r.getClaimAmount();
            this.approvedAmount = r.getApprovedAmount();
            this.deductibleAmount = r.getDeductibleAmount();
            this.settlementAmount = r.getSettlementAmount();
            this.paymentMethod = r.getPaymentMethod();
            this.transactionReferenceId = r.getTransactionReferenceId();
            this.initiatedDate = r.getInitiatedDate();
            this.processedDate = r.getProcessedDate();
            this.completedDate = r.getCompletedDate();
            this.processedBy = r.getProcessedBy();
            this.remarks = r.getRemarks();
        }
    }
}

