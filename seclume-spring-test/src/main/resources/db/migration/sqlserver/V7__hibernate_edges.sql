-- Hibernate edge cases: a JSON column, character and binary LOBs - as plain
-- values and as java.sql.Clob/Blob written from a stream - and a counter
-- that a @Formula reads.
create table zl_note (id bigint identity not null, title varchar(80), words int not null, attributes nvarchar(max), body varchar(max), data varbinary(max), script varchar(max), picture varbinary(max), primary key (id));
