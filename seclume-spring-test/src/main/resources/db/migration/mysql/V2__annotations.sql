-- The same columns in MySQL's spelling.
alter table zl_customer add column version    bigint not null default 0;
alter table zl_customer add column created_at datetime(6);
alter table zl_customer add column updated_at datetime(6);
alter table zl_customer add column status     varchar(20) not null default 'ACTIVE';
alter table zl_customer add column street     varchar(100);
alter table zl_customer add column city       varchar(100);
alter table zl_customer add column notes      longtext;
