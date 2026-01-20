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
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "enrollments")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Enrollment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "employee_id", nullable = false)
    private Employee employee;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_hr_id")
    private Hr assignedHr;

    @Column(nullable = false)
    private String status = "Pending"; // Pending, Approved, Rejected, Active, Cancelled

    @Column(nullable = false)
    private LocalDate enrollmentDate;

    private LocalDate effectiveDate; // Set on approval

    private LocalDate terminationDate;

    @Column(nullable = false)
    private String coverageType; // Individual, Family

    @Column(nullable = false)
    private Double premiumAmount;

    @Column(length = 1000)
    private String requestReason;

    @Column(length = 2000)
    private String remarks; // HR approval/rejection notes

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    private LocalDateTime updatedAt = LocalDateTime.now();

    public Enrollment(Employee employee, Policy policy, String coverageType, Double premiumAmount, String requestReason) {
        this.employee = employee;
        this.policy = policy;
        this.coverageType = coverageType;
        this.premiumAmount = premiumAmount;
        this.requestReason = requestReason;
        this.enrollmentDate = LocalDate.now();
        this.status = "Pending";
        this.createdAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }
}

