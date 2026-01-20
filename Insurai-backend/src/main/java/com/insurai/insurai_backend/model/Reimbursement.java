package com.insurai.insurai_backend.model;

import java.time.LocalDate;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "reimbursements")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Reimbursement {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "claim_id", nullable = false, unique = true)
    private Claim claim;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "employee_id", nullable = false)
    private Employee employee;

    @Column(nullable = false)
    private String status = "Pending"; // Pending, Processing, Completed, Failed

    @Column(nullable = false)
    private Double claimAmount;

    @Column(nullable = false)
    private Double approvedAmount;

    @Column(nullable = false)
    private Double deductibleAmount = 0.0;

    @Column(nullable = false)
    private Double settlementAmount; // Final amount paid

    @Column(nullable = false)
    private String paymentMethod; // Bank Transfer, Cheque, Cash

    private String transactionReferenceId;

    private String bankAccountNumber; // Last 4 digits for verification

    @Column(nullable = false)
    private LocalDate initiatedDate;

    private LocalDate processedDate;

    private LocalDate completedDate;

    private String processedBy; // Admin email who processed

    @Column(length = 2000)
    private String remarks;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime updatedAt = LocalDateTime.now();

    public Reimbursement(Claim claim, Employee employee, Double claimAmount, Double approvedAmount,
                         Double settlementAmount, String paymentMethod) {
        this.claim = claim;
        this.employee = employee;
        this.claimAmount = claimAmount;
        this.approvedAmount = approvedAmount;
        this.deductibleAmount = 0.0;
        this.settlementAmount = settlementAmount;
        this.paymentMethod = paymentMethod;
        this.status = "Pending";
        this.initiatedDate = LocalDate.now();
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
}

