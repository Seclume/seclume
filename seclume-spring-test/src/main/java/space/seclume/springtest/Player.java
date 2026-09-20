package space.seclume.springtest;

import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

/**
 * The many side of the one-to-many, one side of a many-to-many, and the owner
 * of a one-to-one that shares its key.
 *
 * <p>Three association kinds on one entity is not decoration: each produces a
 * different query, and the one-to-one with {@code @MapsId} produces the
 * awkward one - an insert into a second table using a key that was generated
 * for the first, in the same flush.
 */
@Entity
@Table(name = "zl_player")
public class Player {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "label", nullable = false, length = 60)
    private String label;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "team_id")
    private Team team;

    @ManyToMany(cascade = { CascadeType.PERSIST, CascadeType.MERGE })
    @JoinTable(name = "zl_player_skill",
            joinColumns = @JoinColumn(name = "player_id"),
            inverseJoinColumns = @JoinColumn(name = "skill_id"))
    private Set<Skill> skills = new LinkedHashSet<>();

    @OneToOne(mappedBy = "player", cascade = CascadeType.ALL, orphanRemoval = true)
    private PlayerProfile profile;

    protected Player() {
    }

    public Player(String label) {
        this.label = label;
    }

    public Long getId() {
        return id;
    }

    public String getLabel() {
        return label;
    }

    public Team getTeam() {
        return team;
    }

    void setTeam(Team team) {
        this.team = team;
    }

    public Set<Skill> getSkills() {
        return skills;
    }

    public PlayerProfile getProfile() {
        return profile;
    }

    public void setProfile(PlayerProfile profile) {
        this.profile = profile;
        if (profile != null) {
            profile.setPlayer(this);
        }
    }
}
