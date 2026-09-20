-- One row of every type an application maps - the columns are Hibernate's own
-- mapping for this dialect, taken from its schema generator rather than guessed,
-- so that ddl-auto=validate compares like with like.
create table zl_sample (amount number(18,4), day date, duration number(21,0), flag boolean not null, moment timestamp(0), number_value number(10,0), precise binary_double not null, small number(5,0) not null, year_value number(10,0), big_value number(19,0), instant timestamp(9) with time zone, offset_stamp timestamp(9) with time zone, stamp timestamp(9), id raw(16) not null, status varchar2(20 char) check ((status in ('ACTIVE','DORMANT','CLOSED'))), raw_value raw(255), price varchar2(255 char), text varchar2(255 char), primary key (id));
