package space.seclume.springtest;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;

/**
 * {@code @MapsId} - the key of this row is the key of the player it belongs
 * to, and it is never generated here.
 *
 * <p>The interesting part for a driver is the order: the player's identity
 * column is filled by the server during the insert, the value is read back,
 * and it is that value which is bound as this row's key a moment later. If
 * {@code getGeneratedKeys} returns the wrong type - a decimal where a long is
 * wanted, or the row count instead of the key - this is where it shows.
 */
@Entity
@Table(name = "zl_player_profile")
public class PlayerProfile {

    @Id
    @Column(name = "player_id")
    private Long id;

    @OneToOne
    @MapsId
    @JoinColumn(name = "player_id")
    private Player player;

    @Column(name = "bio", length = 200)
    private String bio;

    protected PlayerProfile() {
    }

    public PlayerProfile(String bio) {
        this.bio = bio;
    }

    public Long getId() {
        return id;
    }

    public Player getPlayer() {
        return player;
    }

    void setPlayer(Player player) {
        this.player = player;
    }

    public String getBio() {
        return bio;
    }
}
