CREATE DATABASE projekt_db;
\c projekt_db;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_status') THEN
        CREATE TYPE user_status AS ENUM ('ACTIVE', 'INACTIVE', 'BANNED');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS users (
    user_id         SERIAL PRIMARY KEY,
    username        VARCHAR(50) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    first_name      VARCHAR(50),
    last_name       VARCHAR(50),
    status          user_status NOT NULL DEFAULT 'ACTIVE',
    metadata        JSONB DEFAULT '{}'::jsonb,
    date_created    TIMESTAMP NOT NULL DEFAULT NOW(),
    last_modified   TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    role_id     SERIAL PRIMARY KEY,
    role_name   VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id   SERIAL PRIMARY KEY,
    permission_name VARCHAR(50) NOT NULL UNIQUE,
    description     VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (role_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       INT NOT NULL,
    permission_id INT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles (role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions (permission_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS order_statuses (
    status_id   SERIAL PRIMARY KEY,
    name        VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255)
);

INSERT INTO order_statuses (name, description)
VALUES
  ('PENDING',    'Narudžba zaprimljena, čeka obradu.'),
  ('PROCESSING', 'Narudžba se obrađuje.'),
  ('COMPLETED',  'Narudžba je dovršena.'),
  ('CANCELED',   'Narudžba je otkazana.')
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS orders (
    order_id     SERIAL PRIMARY KEY,
    user_id      INT NOT NULL,
    order_date   TIMESTAMP NOT NULL DEFAULT NOW(),
    total_price  NUMERIC(10,2) NOT NULL,
    status_id    INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (status_id) REFERENCES order_statuses(status_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id        SERIAL PRIMARY KEY,
    table_name    TEXT NOT NULL,
    operation     TEXT NOT NULL,
    changed_by    VARCHAR(50),
    changed_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    old_data      JSONB,
    new_data      JSONB
);

CREATE OR REPLACE FUNCTION log_audit()
RETURNS TRIGGER AS $$
DECLARE
    v_old JSONB;
    v_new JSONB;
    v_operation TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        v_new = to_jsonb(NEW);
        v_operation = 'INSERT';
    ELSIF TG_OP = 'UPDATE' THEN
        v_old = to_jsonb(OLD);
        v_new = to_jsonb(NEW);
        v_operation = 'UPDATE';
    ELSIF TG_OP = 'DELETE' THEN
        v_old = to_jsonb(OLD);
        v_operation = 'DELETE';
    END IF;

    INSERT INTO audit_log(table_name, operation, changed_by, changed_at, old_data, new_data)
    VALUES (TG_TABLE_NAME, v_operation, current_user, NOW(), v_old, v_new);

    RETURN NULL; 
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_audit
AFTER INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW
EXECUTE PROCEDURE log_audit();

CREATE TRIGGER trg_orders_audit
AFTER INSERT OR UPDATE OR DELETE ON orders
FOR EACH ROW
EXECUTE PROCEDURE log_audit();

CREATE TRIGGER trg_roles_audit
AFTER INSERT OR UPDATE OR DELETE ON roles
FOR EACH ROW
EXECUTE PROCEDURE log_audit();

CREATE OR REPLACE FUNCTION update_last_modified()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_modified := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_last_modified
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE PROCEDURE update_last_modified();

CREATE OR REPLACE FUNCTION set_default_order_status()
RETURNS TRIGGER AS $$
DECLARE
    v_pending_id INT;
BEGIN
    IF NEW.status_id IS NULL THEN
       SELECT status_id INTO v_pending_id FROM order_statuses WHERE name = 'PENDING';
       NEW.status_id = v_pending_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_default_order_status
BEFORE INSERT ON orders
FOR EACH ROW
EXECUTE PROCEDURE set_default_order_status();

INSERT INTO roles (role_name, description)
VALUES 
  ('ADMIN',  'System administrator'),
  ('EDITOR', 'Can edit content'),
  ('VIEWER', 'Can only view content')
ON CONFLICT (role_name) DO NOTHING;

INSERT INTO permissions (permission_name, description)
VALUES
  ('CREATE', 'Create content'),
  ('READ',   'Read content'),
  ('UPDATE', 'Update content'),
  ('DELETE', 'Delete content'),
  ('MANAGE_USERS', 'Can manage users')
ON CONFLICT (permission_name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'ADMIN'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'EDITOR'
  AND p.permission_name IN ('CREATE','READ','UPDATE')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'VIEWER'
  AND p.permission_name IN ('READ')
ON CONFLICT DO NOTHING;

INSERT INTO users (username, password_hash, first_name, last_name, status, metadata)
VALUES
  ('admin_user', 'adminpass', 'Jasam', 'Admin', 'ACTIVE', '{"info":"glavni admin"}'),
  ('editor_user','editorpass','Edit', 'Uredivac',   'ACTIVE', '{"department":"marketing"}'),
  ('viewer_user','viewpass',  'View', 'Pogled',    'ACTIVE', '{"department":"it"}')
ON CONFLICT (username) DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u, roles r
WHERE u.username = 'admin_user' AND r.role_name = 'ADMIN'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u, roles r
WHERE u.username = 'editor_user' AND r.role_name = 'EDITOR'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u, roles r
WHERE u.username = 'viewer_user' AND r.role_name = 'VIEWER'
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION fn_apply_vip_discount()
RETURNS TRIGGER AS $$
DECLARE
    v_vip TEXT;
BEGIN
    SELECT (metadata->>'vip')
    INTO v_vip
    FROM users
    WHERE user_id = NEW.user_id;

    IF v_vip = 'true' THEN
        NEW.total_price := NEW.total_price * 0.9;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_vip_discount
BEFORE INSERT ON orders
FOR EACH ROW
EXECUTE PROCEDURE fn_apply_vip_discount();

CREATE OR REPLACE FUNCTION fn_update_order_status_if_user_banned()
RETURNS TRIGGER AS $$
DECLARE
    v_cancel_id INT;
BEGIN
    IF OLD.status <> 'BANNED' AND NEW.status = 'BANNED' THEN
        SELECT status_id
        INTO v_cancel_id
        FROM order_statuses
        WHERE name = 'CANCELED';

        UPDATE orders o
        SET status_id = v_cancel_id
        WHERE o.user_id = NEW.user_id
          AND o.status_id IN (
              SELECT status_id 
              FROM order_statuses
              WHERE name IN ('PENDING','PROCESSING')
          );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_order_status_if_user_banned
AFTER UPDATE ON users
FOR EACH ROW
EXECUTE PROCEDURE fn_update_order_status_if_user_banned();

COMMIT;

