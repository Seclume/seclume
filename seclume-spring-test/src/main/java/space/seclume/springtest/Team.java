package space.seclume.springtest;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import jakarta.persistence.CascadeType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.Table;

/**
 * A one-to-many with an order, and a collection of plain values beside it.
 *
 * <p>{@code @OrderBy} is the part with teeth: the order is the server's, not
 * the application's, so what this proves is that the rows arrive in the order
 * the {@code order by} asked for and that the driver hands them on in that
 * order. A driver that buffers rows and loses their sequence passes every
 * single-row test and fails here.
 *
 * <p>The {@code @ElementCollection} is a second table with no entity behind
 * it, written and read as a set - Hibernate deletes all of it and inserts it
 * again on every change, so it is also a small batch test.
 */
@Entity
@Table(name = "zl_team")
public class Team {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "label", nullable = false, length = 60)
    private String label;

    @OneToMany(mappedBy = "team", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("label asc")
    private List<Player> players = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "zl_team_tag", joinColumns = @JoinColumn(name = "team_id"))
    @Column(name = "tag", length = 30)
    private Set<String> tags = new LinkedHashSet<>();

    protected Team() {
    }

    public Team(String label) {
        this.label = label;
    }

    public Long getId() {
        return id;
    }

    public String getLabel() {
        return label;
    }

    public List<Player> getPlayers() {
        return players;
    }

    public Set<String> getTags() {
        return tags;
    }

    public void add(Player player) {
        players.add(player);
        player.setTeam(this);
    }
}
