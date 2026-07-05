-- src/test/resources/data.sql
INSERT INTO clients (id, name, client_secret, is_active, redirect_url, created_at, updated_at)
VALUES (
           '11111111-1111-1111-1111-111111111111',
           'auth-console',
           '$2a$10$examplebcryptplaceholderhash',
           true,
           'http://localhost:8080/callback',
           NOW(),
           NOW()
       );