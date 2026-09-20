-- One row of every type an application maps - the columns are Hibernate's own
-- mapping for this dialect, taken from its schema generator rather than guessed,
-- so that ddl-auto=validate compares like with like.
create table zl_sample (amount decimal(18,4), day date, duration decimal(21,0), flag bit not null, moment time(0), number_value integer, precise float(53) not null, small smallint not null, year_value integer, big_value bigint, instant datetime(6), offset_stamp datetime(6), stamp datetime(6), id binary(16) not null, price varchar(255), text varchar(255), raw_value varbinary(255), status enum ('ACTIVE','CLOSED','DORMANT'), primary key (id)) engine=InnoDB;
