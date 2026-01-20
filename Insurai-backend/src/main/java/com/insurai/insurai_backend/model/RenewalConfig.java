package com.insurai.insurai_backend.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "renewal_config")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RenewalConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Boolean alertsEnabled = true;

    @Column(nullable = false)
    private Integer firstAlertDays = 30; // Days before expiry for 1st alert

    @Column(nullable = false)
    private Integer secondAlertDays = 15; // Days before expiry for 2nd alert

    @Column(nullable = false)
    private Integer finalAlertDays = 7; // Days before expiry for final alert

    @Column(nullable = false)
    private Boolean autoExpireEnabled = true;

    private LocalDateTime lastModifiedAt = LocalDateTime.now();

    private String lastModifiedBy; // Admin email who last updated config
}

