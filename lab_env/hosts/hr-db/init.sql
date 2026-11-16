-- Dummy HR data (runs once, on the first start of an empty volume). All rows are fake.
-- The database `hr` and the account hr_app come from MARIADB_DATABASE / MARIADB_USER in docker-compose.yml.
USE hr;
CREATE TABLE employees (
    id          int AUTO_INCREMENT PRIMARY KEY,
    name        varchar(100) NOT NULL,
    department  varchar(50)  NOT NULL,
    salary      int,                    -- confidential: a target for "data exfiltration" scenarios
    iban        varchar(34)             -- fake bank accounts
);
INSERT INTO employees (name, department, salary, iban) VALUES
    ('Alice Example', 'IT',      98000, 'DE00 0000 0000 0000 0000 01'),
    ('Bob Example',   'Sales',   61000, 'DE00 0000 0000 0000 0000 02'),
    ('Carol Example', 'R&D',     84000, 'DE00 0000 0000 0000 0000 03'),
    ('Dave Example',  'Finance', 77000, 'DE00 0000 0000 0000 0000 04');
