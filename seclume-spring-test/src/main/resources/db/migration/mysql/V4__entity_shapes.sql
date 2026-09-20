-- The entity shapes: inheritance in all three strategies, composite keys in
-- both spellings, the collection mappings, a shared key and a second table.
-- As with V3 the DDL is Hibernate's own for this dialect, taken from its
-- schema generator rather than written here, so that ddl-auto=validate
-- compares like with like.
create table zl_book (id bigint not null auto_increment, isbn varchar(20) not null, title varchar(120) not null, primary key (id)) engine=InnoDB;
create table zl_book_detail (book_id bigint not null, summary varchar(500), primary key (book_id)) engine=InnoDB;
create table zl_invoice (issued_on date not null, net decimal(12,2), id bigint not null, doc_no varchar(40) not null, primary key (id)) engine=InnoDB;
create table zl_keys (next_value bigint, key_name varchar(255) not null, primary key (key_name)) engine=InnoDB;
insert into zl_keys(key_name, next_value) values ('zl_doc',0);
create table zl_payment (amount decimal(12,2) not null, id bigint not null, paid_at datetime(6) not null, primary key (id)) engine=InnoDB;
create table zl_payment_bank (payment_id bigint not null, iban varchar(34), primary key (payment_id)) engine=InnoDB;
create table zl_payment_card (last_four varchar(4), payment_id bigint not null, primary key (payment_id)) engine=InnoDB;
create table zl_payment_seq (next_val bigint) engine=InnoDB;
insert into zl_payment_seq ( next_val ) values ( 1 );
create table zl_player (id bigint not null auto_increment, team_id bigint, label varchar(60) not null, primary key (id)) engine=InnoDB;
create table zl_player_profile (player_id bigint not null, bio varchar(200), primary key (player_id)) engine=InnoDB;
create table zl_player_skill (player_id bigint not null, skill_id bigint not null, primary key (player_id, skill_id)) engine=InnoDB;
create table zl_receipt (issued_on date not null, id bigint not null, doc_no varchar(40) not null, cashier varchar(60), primary key (id)) engine=InnoDB;
create table zl_seat (seat_row integer not null, section_name varchar(20) not null, note varchar(60), primary key (seat_row, section_name)) engine=InnoDB;
create table zl_skill (id bigint not null auto_increment, label varchar(40) not null, primary key (id)) engine=InnoDB;
create table zl_team (id bigint not null auto_increment, label varchar(60) not null, primary key (id)) engine=InnoDB;
create table zl_team_tag (team_id bigint not null, tag varchar(30)) engine=InnoDB;
create table zl_ticket (seat_no integer not null, event_name varchar(40) not null, holder varchar(60), primary key (seat_no, event_name)) engine=InnoDB;
create table zl_vehicle (payload decimal(10,2), seats integer, id bigint not null auto_increment, kind varchar(16) not null check ((kind in ('CAR','TRUCK'))), label varchar(60) not null, primary key (id)) engine=InnoDB;
alter table zl_book add constraint UK4e2tfdyb6f5kxsyyogr54aw32 unique (isbn);
alter table zl_team_tag add constraint UKa44j7sp8qr7eg10rgfq26i1v7 unique (team_id, tag);
alter table zl_book_detail add constraint FKg91iycnplnkkgutqt9yt622h0 foreign key (book_id) references zl_book (id);
alter table zl_payment_bank add constraint FKsqd8t5u525nj7956qkga74lvb foreign key (payment_id) references zl_payment (id);
alter table zl_payment_card add constraint FKpll1m9xgv8yy3vboalt5ntosy foreign key (payment_id) references zl_payment (id);
alter table zl_player add constraint FKmaujo0aivm1abdepy0mdo2pnc foreign key (team_id) references zl_team (id);
alter table zl_player_profile add constraint FKst9gwteqf9b6tc8cn67yda8kv foreign key (player_id) references zl_player (id);
alter table zl_player_skill add constraint FKsbjn3ne1ovvl001xydi9wukp1 foreign key (skill_id) references zl_skill (id);
alter table zl_player_skill add constraint FK1p905fksonjhyufe4ssnj9s6b foreign key (player_id) references zl_player (id);
alter table zl_team_tag add constraint FK4mf41b5c7vrcct0sbwjbqlcc4 foreign key (team_id) references zl_team (id);
