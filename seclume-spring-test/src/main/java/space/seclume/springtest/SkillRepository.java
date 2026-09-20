package space.seclume.springtest;

import org.springframework.data.jpa.repository.JpaRepository;

/** The other side of the many-to-many. */
public interface SkillRepository extends JpaRepository<Skill, Long> {
}
