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
@Table(name = "renewal_history")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RenewalHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "policy_id", nullable = false)
    private Policy policy;

    @Column(nullable = false)
    private LocalDate oldRenewalDate;

    @Column(nullable = false)
    private LocalDate newRenewalDate;

    @Column(nullable = false)
    private String renewedBy; // Admin/HR email

    @Column(nullable = false)
    private String renewalType; // Manual, Automatic, Expiry

    @Column(nullable = false)
    private LocalDateTime renewedAt = LocalDateTime.now();

    public RenewalHistory(Policy policy, LocalDate oldRenewalDate, LocalDate newRenewalDate,
                          String renewedBy, String renewalType) {
        this.policy = policy;
        this.oldRenewalDate = oldRenewalDate;
        this.newRenewalDate = newRenewalDate;
        this.renewedBy = renewedBy;
        this.renewalType = renewalType;
        this.renewedAt = LocalDateTime.now();
    }
}

