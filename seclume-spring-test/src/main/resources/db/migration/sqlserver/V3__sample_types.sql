-- One row of every type an application maps - the columns are Hibernate's own
-- mapping for this dialect, taken from its schema generator rather than guessed,
-- so that ddl-auto=validate compares like with like.
create table zl_sample (amount numeric(18,4), day date, duration numeric(21,0), flag bit not null, moment time, number_value int, precise float(53) not null, small smallint not null, year_value int, big_value bigint, instant datetimeoffset(7), offset_stamp datetimeoffset(7), stamp datetime2(7), id uniqueidentifier not null, status varchar(20) check ((status in ('ACTIVE','DORMANT','CLOSED'))), price varchar(255), raw_value varbinary(255), text varchar(255), primary key (id));
