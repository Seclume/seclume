package space.seclume.mongospring;

import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

/** A person with what Spring Data maps: an id, a unique index, an embedded value, a list, a version. */
@Document("zl_spring_people")
public class Person {

    @Id
    private String id;

    @Indexed(unique = true)
    private String email;

    private String name;

    private int age;

    private Address address;

    private List<String> tags = List.of();

    @Version
    private Long version;

    public record Address(String city, String zip) {
    }

    public Person() {
    }

    public Person(String email, String name, int age, String city, List<String> tags) {
        this.email = email;
        this.name = name;
        this.age = age;
        this.address = new Address(city, "0000");
        this.tags = tags;
    }

    public String getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    public Address getAddress() {
        return address;
    }

    public List<String> getTags() {
        return tags;
    }

    public Long getVersion() {
        return version;
    }
}
