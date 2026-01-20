package com.insurai.insurai_backend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.insurai.insurai_backend.model.Dependent;
import com.insurai.insurai_backend.model.Enrollment;

@Repository
public interface DependentRepository extends JpaRepository<Dependent, Long> {

    List<Dependent> findByEnrollment(Enrollment enrollment);

    List<Dependent> findByEnrollmentId(Long enrollmentId);

    void deleteByEnrollment(Enrollment enrollment);
}

