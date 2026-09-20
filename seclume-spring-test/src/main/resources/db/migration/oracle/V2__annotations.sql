-- The same columns in Oracle's spelling, in one statement as Oracle prefers.
alter table zl_customer add (
    version    number(19) default 0 not null,
    created_at timestamp,
    updated_at timestamp,
    status     varchar2(20) default 'ACTIVE' not null,
    street     varchar2(100),
    city       varchar2(100),
    notes      clob
);
