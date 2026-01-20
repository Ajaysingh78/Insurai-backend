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
@Table(name = "dependents")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Dependent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "enrollment_id", nullable = false)
    private Enrollment enrollment;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String relationship; // Spouse, Child, Parent

    @Column(nullable = false)
    private LocalDate dateOfBirth;

    private String dependentId; // Internal/govt ID for dependent

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    public Dependent(Enrollment enrollment, String name, String relationship, LocalDate dateOfBirth, String dependentId) {
        this.enrollment = enrollment;
        this.name = name;
        this.relationship = relationship;
        this.dateOfBirth = dateOfBirth;
        this.dependentId = dependentId;
        this.createdAt = LocalDateTime.now();
    }
}

