package com.insurai.insurai_backend.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.insurai.insurai_backend.model.Employee;
import com.insurai.insurai_backend.model.Enrollment;
import com.insurai.insurai_backend.model.Hr;
import com.insurai.insurai_backend.model.Policy;

@Repository
public interface EnrollmentRepository extends JpaRepository<Enrollment, Long> {

    List<Enrollment> findByEmployee(Employee employee);

    List<Enrollment> findByEmployeeId(Long employeeId);

    List<Enrollment> findByStatus(String status);

    List<Enrollment> findByPolicy(Policy policy);

    List<Enrollment> findByPolicyAndStatus(Policy policy, String status);

    List<Enrollment> findByAssignedHr(Hr hr);

    List<Enrollment> findByAssignedHrAndStatus(Hr hr, String status);

    Optional<Enrollment> findByEmployeeAndPolicyAndStatusNot(Employee employee, Policy policy, String status);

    @Query("SELECT COUNT(e) FROM Enrollment e WHERE e.policy = :policy AND e.status = :status")
    Long countByPolicyAndStatus(@Param("policy") Policy policy, @Param("status") String status);

    @Query("SELECT COUNT(e) FROM Enrollment e WHERE e.status = :status")
    Long countByStatus(@Param("status") String status);

    @Query("SELECT e FROM Enrollment e WHERE e.employee.id = :employeeId AND e.status IN ('Approved', 'Active')")
    List<Enrollment> findActiveEnrollmentsByEmployeeId(@Param("employeeId") Long employeeId);

    @Query("SELECT e FROM Enrollment e WHERE e.policy.id = :policyId AND e.status IN ('Approved', 'Active')")
    List<Enrollment> findActiveEnrollmentsByPolicyId(@Param("policyId") Long policyId);
}

