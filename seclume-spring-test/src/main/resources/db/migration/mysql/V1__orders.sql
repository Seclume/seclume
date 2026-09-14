-- The same schema in MySQL's spelling. Deliberately ordinary SQL: what is
-- being tested is the driver, not the schema.
create table zl_customer (
    id       bigint auto_increment primary key,
    name     varchar(100) not null,
    email    varchar(200) not null unique
) engine=innodb;

create table zl_order (
    id          bigint auto_increment primary key,
    customer_id bigint not null,
    placed_at   datetime(6) not null,
    total       decimal(12, 2) not null,
    constraint zl_order_customer_fk foreign key (customer_id) references zl_customer (id)
) engine=innodb;

create index zl_order_customer on zl_order (customer_id);
