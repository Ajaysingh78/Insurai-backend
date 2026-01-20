package com.insurai.insurai_backend.repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.insurai.insurai_backend.model.Claim;
import com.insurai.insurai_backend.model.Employee;
import com.insurai.insurai_backend.model.Reimbursement;

@Repository
public interface ReimbursementRepository extends JpaRepository<Reimbursement, Long> {

    Optional<Reimbursement> findByClaim(Claim claim);

    Optional<Reimbursement> findByClaimId(Long claimId);

    List<Reimbursement> findByStatus(String status);

    List<Reimbursement> findByEmployee(Employee employee);

    List<Reimbursement> findByEmployeeId(Long employeeId);

    List<Reimbursement> findByEmployeeAndStatus(Employee employee, String status);

    List<Reimbursement> findByProcessedDateBetween(LocalDate start, LocalDate end);

    List<Reimbursement> findByCompletedDateBetween(LocalDate start, LocalDate end);

    @Query("SELECT SUM(r.settlementAmount) FROM Reimbursement r WHERE r.status = :status AND r.completedDate BETWEEN :start AND :end")
    Double sumTotalAmountByStatusAndDateRange(@Param("status") String status,
                                              @Param("start") LocalDate start,
                                              @Param("end") LocalDate end);

    @Query("SELECT COUNT(r) FROM Reimbursement r WHERE r.status = :status")
    Long countByStatus(@Param("status") String status);

    boolean existsByClaim(Claim claim);
}

