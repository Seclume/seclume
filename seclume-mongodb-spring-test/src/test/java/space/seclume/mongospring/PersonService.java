package space.seclume.mongospring;

import java.util.List;

import org.springframework.transaction.annotation.Transactional;

/** Two writes in one transaction - both, or, when the second step fails, neither. */
public class PersonService {

    private final PersonRepository people;

    public PersonService(PersonRepository people) {
        this.people = people;
    }

    @Transactional
    public void saveBoth(Person first, Person second) {
        people.save(first);
        people.save(second);
    }

    @Transactional
    public void saveThenFail(Person first, Person second) {
        people.saveAll(List.of(first, second));
        throw new IllegalStateException("the second step failed");
    }
}
