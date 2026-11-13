-- 0003: Transaction-committed security invalidation for changes made by any API instance.
-- LISTEN/NOTIFY is NOT durable; consumers must also verify authorization on delivery.
CREATE OR REPLACE FUNCTION nexora_notify_security_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME = 'sessions' AND TG_OP = 'DELETE' THEN
  PERFORM pg_notify('nexora_security',json_build_object('kind','session','user',OLD.user_id,'hash',OLD.token_hash)::text);
 ELSIF TG_TABLE_NAME = 'developer_apps' THEN
  IF TG_OP = 'DELETE' OR (TG_OP = 'UPDATE' AND
      (OLD.bot_token_hash IS DISTINCT FROM NEW.bot_token_hash OR OLD.revoked_at IS DISTINCT FROM NEW.revoked_at)) THEN
   PERFORM pg_notify('nexora_security',json_build_object('kind','bot','app',OLD.id)::text);
  END IF;
 ELSIF TG_TABLE_NAME = 'guild_members' AND TG_OP = 'DELETE' THEN
  PERFORM pg_notify('nexora_security',json_build_object('kind','member','user',OLD.user_id,'guild',OLD.guild_id)::text);
 ELSIF TG_TABLE_NAME = 'guild_bots' AND TG_OP = 'DELETE' THEN
  PERFORM pg_notify('nexora_security',json_build_object('kind','bot_uninstall','app',OLD.app_id,'guild',OLD.guild_id)::text);
 ELSIF TG_TABLE_NAME = 'guild_bots' AND TG_OP = 'UPDATE' AND
       OLD.can_read_events = true AND NEW.can_read_events = false THEN
  PERFORM pg_notify('nexora_security',json_build_object('kind','bot_uninstall','app',OLD.app_id,'guild',OLD.guild_id)::text);
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS nexora_sessions_invalidation ON sessions;
CREATE TRIGGER nexora_sessions_invalidation AFTER DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION nexora_notify_security_change();
DROP TRIGGER IF EXISTS nexora_bot_credentials_invalidation ON developer_apps;
CREATE TRIGGER nexora_bot_credentials_invalidation AFTER UPDATE OR DELETE ON developer_apps FOR EACH ROW EXECUTE FUNCTION nexora_notify_security_change();
DROP TRIGGER IF EXISTS nexora_membership_invalidation ON guild_members;
CREATE TRIGGER nexora_membership_invalidation AFTER DELETE ON guild_members FOR EACH ROW EXECUTE FUNCTION nexora_notify_security_change();
DROP TRIGGER IF EXISTS nexora_bot_install_invalidation ON guild_bots;
CREATE TRIGGER nexora_bot_install_invalidation AFTER UPDATE OR DELETE ON guild_bots FOR EACH ROW EXECUTE FUNCTION nexora_notify_security_change();
