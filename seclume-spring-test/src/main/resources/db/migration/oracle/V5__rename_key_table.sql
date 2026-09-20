-- The table the @GeneratedValue(TABLE) counter lives in, renamed.
-- "zl_keys" is the driver's own test table on more than one of the four
-- servers, and those tests drop it - so an application table of that name
-- disappears in the middle of a build. The name is the whole change; the
-- shape is still Hibernate's.
-- No drop here: Flyway's Oracle parser does not take "if exists" on a
-- statement like this, and the table is already gone on this server -
-- the driver's own tests dropped it, which is what started all of this.
create table zl_gen_keys (next_value number(19,0), key_name varchar2(255 char) not null, primary key (key_name));
insert into zl_gen_keys(key_name, next_value) values ('zl_doc',0);
