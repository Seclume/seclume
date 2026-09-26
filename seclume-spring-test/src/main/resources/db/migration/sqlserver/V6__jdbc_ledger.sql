-- For the JdbcTemplate and transaction tests: plain tables no entity maps,
-- so that what is under test is Spring JDBC and the driver, not Hibernate.
create table sp_ledger (
    id      int primary key,
    note    varchar(200),
    amount  decimal(12, 2),
    created datetime2
);

create table sp_ledger_auto (
    id   int identity primary key,
    note varchar(200)
);
