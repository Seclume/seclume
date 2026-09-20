-- One row of every type an application maps - the columns are Hibernate's own
-- mapping for this dialect, taken from its schema generator rather than guessed,
-- so that ddl-auto=validate compares like with like.
create table zl_sample (amount numeric(18,4), day date, duration numeric(21,0), flag boolean not null, moment time(0), number_value integer, precise float(53) not null, small smallint not null, year_value integer, big_value bigint, instant timestamp(6) with time zone, offset_stamp timestamp(6) with time zone, stamp timestamp(6), id uuid not null, status varchar(20) check ((status in ('ACTIVE','DORMANT','CLOSED'))), price varchar(255), text varchar(255), raw_value bytea, primary key (id));
