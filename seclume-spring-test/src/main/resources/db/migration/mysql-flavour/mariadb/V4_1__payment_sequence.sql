-- MariaDB has sequences (10.3 and later), and Hibernate's MariaDB dialect
-- expects a real one for @SequenceGenerator.
create sequence zl_payment_seq start with 1 increment by 1;
