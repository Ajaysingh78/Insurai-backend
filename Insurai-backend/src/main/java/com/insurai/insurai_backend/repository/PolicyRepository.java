package com.insurai.insurai_backend.repository;

import java.time.LocalDate;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.insurai.insurai_backend.model.Policy;

@Repository
public interface PolicyRepository extends JpaRepository<Policy, Long> {

    // Find all active policies
    List<Policy> findByPolicyStatus(String policyStatus);

    // Find policies by type
    List<Policy> findByPolicyType(String policyType);

    // Find policies by provider
    List<Policy> findByProviderName(String providerName);

    // Find expired active policies (renewal date passed but still marked Active)
    @Query("SELECT p FROM Policy p WHERE p.renewalDate < :date AND p.policyStatus = 'Active'")
    List<Policy> findExpiredActivePolicies(@Param("date") LocalDate date);

    // Find policies expiring between two dates
    @Query("SELECT p FROM Policy p WHERE p.renewalDate BETWEEN :startDate AND :endDate AND p.policyStatus = 'Active'")
    List<Policy> findPoliciesExpiringBetween(@Param("startDate") LocalDate startDate, @Param("endDate") LocalDate endDate);

    // Find policies by renewal date between dates
    List<Policy> findByRenewalDateBetween(LocalDate startDate, LocalDate endDate);

    // Count policies by status
    long countByPolicyStatus(String policyStatus);

    // Count policies by renewal date between dates and status
    long countByRenewalDateBetweenAndPolicyStatus(LocalDate startDate, LocalDate endDate, String policyStatus);
}
