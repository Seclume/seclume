-- The same columns in SQL Server's spelling: datetime2 rather than timestamp,
-- and varchar(max) for the large text.
alter table zl_customer add version    bigint not null default 0;
alter table zl_customer add created_at datetime2(6);
alter table zl_customer add updated_at datetime2(6);
alter table zl_customer add status     varchar(20) not null default 'ACTIVE';
alter table zl_customer add street     varchar(100);
alter table zl_customer add city       varchar(100);
alter table zl_customer add notes      varchar(max);
