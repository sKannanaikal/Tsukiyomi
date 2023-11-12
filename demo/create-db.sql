ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'password123';

CREATE DATABASE users;
USE users;

CREATE TABLE credentials (
	id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
	username VARCHAR(25) NOT NULL UNIQUE,
	password VARCHAR(40) NOT NULL
);

INSERT INTO credentials (username, password) VALUES ("Luke", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
INSERT INTO credentials (username, password) VALUES ("Jeff", "cbfdac6008f9cab4083784cbd1874f76618d2a97");
INSERT INTO credentials (username, password) VALUES ("Mark", "e6b6afbd6d76bb5d2041542d7d2e3fac5bb05593");



