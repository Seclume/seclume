-- Hibernate edge cases: a JSON column, character and binary LOBs - as plain
-- values and as java.sql.Clob/Blob written from a stream - and a counter
-- that a @Formula reads.
create table zl_note (id bigint not null auto_increment, title varchar(80), words integer not null, attributes json, body longtext, data longblob, script longtext, picture longblob, primary key (id)) engine=InnoDB;
