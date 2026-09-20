-- The entity shapes: inheritance in all three strategies, composite keys in
-- both spellings, the collection mappings, a shared key and a second table.
-- As with V3 the DDL is Hibernate's own for this dialect, taken from its
-- schema generator rather than written here, so that ddl-auto=validate
-- compares like with like.
create sequence zl_payment_seq start with 1 increment by 1;
create table zl_book (id bigint identity not null, isbn varchar(20) not null, title varchar(120) not null, primary key (id));
create table zl_book_detail (book_id bigint not null, summary varchar(500), primary key (book_id));
create table zl_invoice (issued_on date not null, net numeric(12,2), id bigint not null, doc_no varchar(40) not null, primary key (id));
create table zl_keys (next_value bigint, key_name varchar(255) not null, primary key (key_name));
insert into zl_keys(key_name, next_value) values ('zl_doc',0);
create table zl_payment (amount numeric(12,2) not null, id bigint not null, paid_at datetime2(7) not null, primary key (id));
create table zl_payment_bank (payment_id bigint not null, iban varchar(34), primary key (payment_id));
create table zl_payment_card (last_four varchar(4), payment_id bigint not null, primary key (payment_id));
create table zl_player (id bigint identity not null, team_id bigint, label varchar(60) not null, primary key (id));
create table zl_player_profile (player_id bigint not null, bio varchar(200), primary key (player_id));
create table zl_player_skill (player_id bigint not null, skill_id bigint not null, primary key (player_id, skill_id));
create table zl_receipt (issued_on date not null, id bigint not null, doc_no varchar(40) not null, cashier varchar(60), primary key (id));
create table zl_seat (seat_row int not null, section_name varchar(20) not null, note varchar(60), primary key (seat_row, section_name));
create table zl_skill (id bigint identity not null, label varchar(40) not null, primary key (id));
create table zl_team (id bigint identity not null, label varchar(60) not null, primary key (id));
create table zl_team_tag (team_id bigint not null, tag varchar(30));
create table zl_ticket (seat_no int not null, event_name varchar(40) not null, holder varchar(60), primary key (seat_no, event_name));
create table zl_vehicle (payload numeric(10,2), seats int, id bigint identity not null, kind varchar(16) not null check ((kind in ('CAR','TRUCK'))), label varchar(60) not null, primary key (id));
alter table zl_book add constraint UK4e2tfdyb6f5kxsyyogr54aw32 unique (isbn);
create unique nonclustered index UKa44j7sp8qr7eg10rgfq26i1v7 on zl_team_tag (team_id, tag) where tag is not null;
alter table zl_book_detail add constraint FKg91iycnplnkkgutqt9yt622h0 foreign key (book_id) references zl_book;
alter table zl_payment_bank add constraint FKsqd8t5u525nj7956qkga74lvb foreign key (payment_id) references zl_payment;
alter table zl_payment_card add constraint FKpll1m9xgv8yy3vboalt5ntosy foreign key (payment_id) references zl_payment;
alter table zl_player add constraint FKmaujo0aivm1abdepy0mdo2pnc foreign key (team_id) references zl_team;
alter table zl_player_profile add constraint FKst9gwteqf9b6tc8cn67yda8kv foreign key (player_id) references zl_player;
alter table zl_player_skill add constraint FKsbjn3ne1ovvl001xydi9wukp1 foreign key (skill_id) references zl_skill;
alter table zl_player_skill add constraint FK1p905fksonjhyufe4ssnj9s6b foreign key (player_id) references zl_player;
alter table zl_team_tag add constraint FK4mf41b5c7vrcct0sbwjbqlcc4 foreign key (team_id) references zl_team;
