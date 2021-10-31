create table users(
id serial primary key ,
fullname varchar(100) not null,
username varchar(50) not null,
password varchar(255) not null,
email varchar(50) not null);