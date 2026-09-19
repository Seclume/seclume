-- The same schema in SQL Server's spelling. Deliberately ordinary SQL: what is
-- being tested is the driver, not the schema.
--
-- Two differences from the others are the database's, not ours: identity is a
-- column property rather than a default, and there is no "timestamp" type that
-- means a point in time - "timestamp" in SQL Server is a row version, so a
-- column that holds a date has to say datetime2.
create table zl_customer (
    id       bigint identity(1, 1) primary key,
    name     varchar(100) not null,
    email    varchar(200) not null unique
);

create table zl_order (
    id          bigint identity(1, 1) primary key,
    customer_id bigint not null,
    placed_at   datetime2(6) not null,
    total       numeric(12, 2) not null,
    constraint zl_order_customer_fk foreign key (customer_id) references zl_customer (id)
);

create index zl_order_customer on zl_order (customer_id);
