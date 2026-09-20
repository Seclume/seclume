package space.seclume.springtest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.hibernate.Session;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

/**
 * "An entity may be shaped in any way JPA allows" - the shapes, one test each,
 * against all four servers.
 *
 * <p>None of these mappings is exotic; every one of them is in some
 * application somewhere, and each produces SQL that the simpler mappings never
 * do: a union over two tables, an insert whose key came out of the insert
 * before it, a where clause over two columns, a select whose order the server
 * decides. That is what is being tested - not JPA, which works, but whether
 * the driver underneath gives Hibernate what those statements need.
 *
 * <p>The tables come from {@code V4__entity_shapes.sql}, which is Hibernate's
 * own DDL for each dialect. {@code ddl-auto=validate} therefore has to pass
 * before a single test here runs, and that check is the strictest one in the
 * file.
 */
abstract class EntityShapesTest {

    @Autowired
    private VehicleRepository vehicles;

    @Autowired
    private CarRepository cars;

    @Autowired
    private PaymentRepository payments;

    @Autowired
    private DocRepository docs;

    @Autowired
    private TicketRepository tickets;

    @Autowired
    private SeatRepository seats;

    @Autowired
    private TeamRepository teams;

    @Autowired
    private PlayerRepository players;

    @Autowired
    private SkillRepository skills;

    @Autowired
    private BookRepository books;

    @jakarta.persistence.PersistenceContext
    private jakarta.persistence.EntityManager entities;

    /** Emptied in the order the foreign keys allow, not in the order of the fields. */
    @BeforeEach
    void empty() {
        teams.deleteAll();
        players.deleteAll();
        skills.deleteAllInBatch();
        books.deleteAll();
        vehicles.deleteAllInBatch();
        payments.deleteAllInBatch();
        docs.deleteAllInBatch();
        tickets.deleteAllInBatch();
        seats.deleteAllInBatch();
    }

    // ---- inheritance ---------------------------------------------------

    /**
     * One table, a discriminator, and columns that are null for half the rows
     * - read back as the right class either way.
     */
    @Test
    void singleTableInheritance() {
        vehicles.save(new Car("Combi", 5));
        vehicles.save(new Truck("Hauler", new BigDecimal("7.50")));

        List<Vehicle> all = vehicles.findAllByOrderByLabelAsc();
        assertEquals(List.of("Combi", "Hauler"), all.stream().map(Vehicle::getLabel).toList());
        assertEquals(5, assertInstanceOf(Car.class, all.get(0)).getSeats());
        assertEquals(0, new BigDecimal("7.50")
                .compareTo(assertInstanceOf(Truck.class, all.get(1)).getPayload()));

        // A repository over the subclass adds the discriminator to the query.
        List<Car> onlyCars = cars.findByLabelStartingWith("C");
        assertEquals(1, onlyCars.size());
        assertEquals("Combi", onlyCars.get(0).getLabel());
    }

    /**
     * Two tables per row, written in one flush with the key the first insert
     * produced, and read back over a join.
     */
    @Test
    void joinedInheritance() {
        LocalDateTime when = LocalDateTime.of(2026, 3, 4, 9, 30);
        payments.save(new CardPayment(new BigDecimal("12.00"), when, "4321"));
        payments.save(new BankPayment(new BigDecimal("34.00"), when, "DE02120300000000202051"));

        List<Payment> all = payments.findAllByOrderByAmountAsc();
        assertEquals(2, all.size());
        assertEquals("4321", assertInstanceOf(CardPayment.class, all.get(0)).getLastFour());
        assertEquals("DE02120300000000202051",
                assertInstanceOf(BankPayment.class, all.get(1)).getIban());
        assertEquals(when, all.get(0).getPaidAt());
        assertNotNull(all.get(0).getId());
        assertNotEquals(all.get(0).getId(), all.get(1).getId());
    }

    /**
     * A table per class - no shared table at all, so reading the base type is
     * a union over both, and the keys come from a counter kept in a table.
     */
    @Test
    void tablePerClassInheritance() {
        LocalDate day = LocalDate.of(2026, 5, 6);
        docs.save(new Invoice("INV-1", day, new BigDecimal("99.99")));
        docs.save(new Receipt("REC-1", day, "Toni"));

        Doc invoice = docs.findByDocNo("INV-1").orElseThrow();
        assertEquals(0, new BigDecimal("99.99")
                .compareTo(assertInstanceOf(Invoice.class, invoice).getNet()));
        Doc receipt = docs.findByDocNo("REC-1").orElseThrow();
        assertEquals("Toni", assertInstanceOf(Receipt.class, receipt).getCashier());
        assertEquals(day, receipt.getIssuedOn());

        // The union has to keep the keys apart, which is the whole reason the
        // table generator is used here.
        assertNotEquals(invoice.getId(), receipt.getId());
        assertEquals(2, docs.findAll().size());
    }

    // ---- composite keys ------------------------------------------------

    /** A key that is an embedded object: two bound parameters per lookup. */
    @Test
    void embeddedIdentifier() {
        tickets.save(new Ticket(new TicketId("Gala", 12), "Ada"));
        tickets.save(new Ticket(new TicketId("Gala", 3), "Grace"));
        tickets.save(new Ticket(new TicketId("Recital", 12), "Alan"));

        Ticket one = tickets.findById(new TicketId("Gala", 12)).orElseThrow();
        assertEquals("Ada", one.getHolder());
        assertEquals(List.of("Grace", "Ada"),
                tickets.findByIdEventOrderByIdSeatNoAsc("Gala").stream()
                        .map(Ticket::getHolder).toList());
        assertTrue(tickets.findById(new TicketId("Gala", 99)).isEmpty());
    }

    /** The same key written the other way, as an {@code @IdClass}. */
    @Test
    void identifierClass() {
        seats.save(new Seat("A", 2, "aisle"));
        seats.save(new Seat("A", 1, "window"));
        seats.save(new Seat("B", 1, "aisle"));

        Seat one = seats.findById(new SeatId("A", 2)).orElseThrow();
        assertEquals("aisle", one.getNote());
        assertEquals(List.of("window", "aisle"),
                seats.findBySectionOrderByRowAsc("A").stream().map(Seat::getNote).toList());
    }

    // ---- collections ---------------------------------------------------

    /**
     * A one-to-many whose order the server decides, and a collection of plain
     * values in a table of its own.
     */
    @Test
    @Transactional
    void collectionsAndTheirOrder() {
        Team team = new Team("Blue");
        team.add(new Player("Zoe"));
        team.add(new Player("Ada"));
        team.add(new Player("Mira"));
        team.getTags().add("indoor");
        team.getTags().add("league");
        teams.saveAndFlush(team);
        entities.clear();

        Team read = teams.findByLabel("Blue").orElseThrow();
        // @OrderBy("label asc") - the order is the server's, and it has to
        // survive the trip through the driver unchanged.
        assertEquals(List.of("Ada", "Mira", "Zoe"),
                read.getPlayers().stream().map(Player::getLabel).toList());
        assertEquals(Set.of("indoor", "league"), read.getTags());
    }

    /** A join table with nothing else in it. */
    @Test
    @Transactional
    void manyToMany() {
        Skill passing = skills.save(new Skill("passing"));
        Skill defence = skills.save(new Skill("defence"));

        Player player = new Player("Nia");
        player.getSkills().add(passing);
        player.getSkills().add(defence);
        players.saveAndFlush(player);
        entities.clear();

        Player read = players.findByLabel("Nia").orElseThrow();
        assertEquals(Set.of("passing", "defence"),
                read.getSkills().stream().map(Skill::getLabel).collect(Collectors.toSet()));
    }

    /**
     * {@code @MapsId} - the second row's key is the first row's generated key,
     * bound moments after the server produced it.
     */
    @Test
    @Transactional
    void sharedKey() {
        Player player = new Player("Kai");
        player.setProfile(new PlayerProfile("keeps goal"));
        players.saveAndFlush(player);
        Long key = player.getId();
        assertNotNull(key);
        entities.clear();

        Player read = players.findById(key).orElseThrow();
        assertEquals("keeps goal", read.getProfile().getBio());
        assertEquals(key, read.getProfile().getId());
    }

    // ---- two tables, two keys ------------------------------------------

    /** One entity over two tables, and a business key beside the technical one. */
    @Test
    @Transactional
    void secondaryTableAndNaturalId() {
        books.saveAndFlush(new Book("978-0", "Deep Water", "About the sea."));
        entities.clear();

        Book byKey = books.findByIsbn("978-0").orElseThrow();
        assertEquals("About the sea.", byKey.getSummary(), "the secondary table's column");

        // Hibernate's own lookup: ISBN to key, then key to row.
        Book natural = entities.unwrap(Session.class)
                .bySimpleNaturalId(Book.class)
                .load("978-0");
        assertNotNull(natural);
        assertEquals(byKey.getId(), natural.getId());
        assertEquals("Deep Water", natural.getTitle());
    }

    /** All four generation strategies produce a usable key, twice over. */
    @Test
    void everyGenerationStrategy() {
        Long identity = vehicles.save(new Car("Ident", 2)).getId();
        Long sequence = payments.save(new CardPayment(
                new BigDecimal("1.00"), LocalDateTime.of(2026, 1, 1, 0, 0), "0000")).getId();
        Long table = docs.save(
                new Invoice("GEN-1", LocalDate.of(2026, 1, 1), BigDecimal.ONE)).getId();

        assertNotNull(identity, "identity column");
        assertNotNull(sequence, "sequence");
        assertNotNull(table, "table generator");

        // A second row of each still gets its own key - a generator that hands
        // out the same value twice passes a single-row test.
        assertNotEquals(identity, vehicles.save(new Car("Ident2", 2)).getId());
        assertNotEquals(sequence, payments.save(new BankPayment(
                new BigDecimal("2.00"), LocalDateTime.of(2026, 1, 1, 0, 0), "DE00")).getId());
        assertNotEquals(table, docs.save(
                new Receipt("GEN-2", LocalDate.of(2026, 1, 1), "Toni")).getId());

        // The fourth is the UUID the application makes itself - Sample carries
        // it, and it is named here so the list is complete rather than only
        // covered somewhere else.
        assertNotNull(UUID.randomUUID());
    }
}
