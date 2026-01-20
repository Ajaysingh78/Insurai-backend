package com.insurai.insurai_backend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.insurai.insurai_backend.model.Policy;
import com.insurai.insurai_backend.model.RenewalHistory;

@Repository
public interface RenewalHistoryRepository extends JpaRepository<RenewalHistory, Long> {

    List<RenewalHistory> findByPolicy(Policy policy);

    List<RenewalHistory> findByPolicyId(Long policyId);

    List<RenewalHistory> findByRenewalType(String renewalType);

    List<RenewalHistory> findByPolicyIdOrderByRenewedAtDesc(Long policyId);
}
