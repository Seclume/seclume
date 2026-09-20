-- The table the @GeneratedValue(TABLE) counter lives in, renamed.
-- "zl_keys" is the driver's own test table on more than one of the four
-- servers, and those tests drop it - so an application table of that name
-- disappears in the middle of a build. The name is the whole change; the
-- shape is still Hibernate's.
drop table if exists zl_keys;
create table zl_gen_keys (next_value bigint, key_name varchar(255) not null, primary key (key_name)) engine=InnoDB;
insert into zl_gen_keys(key_name, next_value) values ('zl_doc',0);
