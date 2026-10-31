-- MySQL has no sequences: Hibernate keeps @SequenceGenerator's value in a table.
create table zl_payment_seq (next_val bigint) engine=InnoDB;
insert into zl_payment_seq ( next_val ) values ( 1 );
