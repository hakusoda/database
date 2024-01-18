
SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

ALTER SCHEMA "public" OWNER TO "postgres";

CREATE EXTENSION IF NOT EXISTS "pg_cron" WITH SCHEMA "public";

CREATE EXTENSION IF NOT EXISTS "pg_net" WITH SCHEMA "extensions";

CREATE EXTENSION IF NOT EXISTS "pgsodium" WITH SCHEMA "pgsodium";

CREATE SCHEMA IF NOT EXISTS "supabase_migrations";

ALTER SCHEMA "supabase_migrations" OWNER TO "postgres";

CREATE EXTENSION IF NOT EXISTS "pg_graphql" WITH SCHEMA "graphql";

CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";

CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";

CREATE EXTENSION IF NOT EXISTS "pgjwt" WITH SCHEMA "extensions";

CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";

CREATE OR REPLACE FUNCTION "public"."add_mellow_user_server_used_connection"(sub text, type smallint, user_id uuid) RETURNS void
    LANGUAGE "sql"
    AS $$merge into public.mellow_user_server_used_connections
using (values (type, user_id)) as source (type, user_id)
on mellow_user_server_used_connections.type = source.type and mellow_user_server_used_connections.user_id = source.user_id
when matched then
  update set last_used_at = now()
when not matched then
  insert (sub, type, user_id)
  values (sub, type, user_id)$$;

ALTER FUNCTION "public"."add_mellow_user_server_used_connection"(sub text, type smallint, user_id uuid) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."add_mellow_user_server_used_connection2"(sub text, type smallint, user_id uuid, server_id text) RETURNS void
    LANGUAGE "sql"
    AS $$merge into public.mellow_user_server_used_connections
using (values (type, user_id, server_id)) as source (type, user_id, server_id)
on mellow_user_server_used_connections.type = source.type and mellow_user_server_used_connections.user_id = source.user_id and mellow_user_server_used_connections.server_id = source.server_id
when matched then
  update set last_used_at = now()
when not matched then
  insert (sub, type, user_id, server_id)
  values (sub, type, user_id, server_id)$$;

ALTER FUNCTION "public"."add_mellow_user_server_used_connection2"(sub text, type smallint, user_id uuid, server_id text) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."auth_to_connections"() RETURNS void
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$declare
  i record;
begin
  for i in select id, user_id from auth.identities where provider = 'github'
  loop
    insert into public.user_connections (sub, name, type, user_id)
    values (i.id, 'UNKNOWN', 1, i.user_id);
  end loop;
end;$$;

ALTER FUNCTION "public"."auth_to_connections"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."create_new_user_profile"() RETURNS trigger
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$begin
  insert into public.users (id, username)
    values (new.id, new.id);
  update public.users set username = format('user_%s', internal_id) where id = new.id;
  return new;
end;$$;

ALTER FUNCTION "public"."create_new_user_profile"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."generate_absolutesolver_hmac"(secret text, message text) RETURNS text
    LANGUAGE "plpgsql"
    AS $$DECLARE
    hmac_result bytea;
BEGIN
    hmac_result := hmac(message::bytea, secret::bytea, 'sha256');
    RETURN encode(hmac_result, 'hex');
END;$$;

ALTER FUNCTION "public"."generate_absolutesolver_hmac"(secret text, message text) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."get_relevant_discord_server_links"(server_id text) RETURNS record
    LANGUAGE "sql"
    AS $$select * from mellow_links where relevant_ids[1] = server_id;$$;

ALTER FUNCTION "public"."get_relevant_discord_server_links"(server_id text) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."get_user_by_discord_user_id"(discord_user_id text) RETURNS record
    LANGUAGE "sql"
    AS $$select * from users t1 where t1.id in (select user_id from user_connections c where c.type = 0 and t1.id = c.user_id)$$;

ALTER FUNCTION "public"."get_user_by_discord_user_id"(discord_user_id text) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."mellow_server_accessible_by_user"(target_user_id uuid, owner_user_id uuid, owner_team_id uuid) RETURNS boolean
    LANGUAGE "sql"
    AS $$select (owner_user_id = target_user_id or (owner_team_id is not null and exists(select 1 from team_members where user_id = target_user_id and team_id = owner_team_id)))$$;

ALTER FUNCTION "public"."mellow_server_accessible_by_user"(target_user_id uuid, owner_user_id uuid, owner_team_id uuid) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."mellow_server_accessible_by_user2"(server_id text, user_id uuid) RETURNS boolean
    LANGUAGE "sql"
    AS $$select exists(select 1 from mellow_servers where id = server_id and mellow_server_accessible_by_user(user_id, owner_user_id, owner_team_id))$$;

ALTER FUNCTION "public"."mellow_server_accessible_by_user2"(server_id text, user_id uuid) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."mellow_to_connections"() RETURNS void
    LANGUAGE "plpgsql"
    AS $$declare
  i record;
begin
  for i in select id, mellow_ids from public.users where cardinality(mellow_ids) = 1
  loop
    insert into public.user_connections (sub, name, type, user_id)
    values (i.mellow_ids[1], 'UNKNOWN', 0, i.id);
  end loop;
end;$$;

ALTER FUNCTION "public"."mellow_to_connections"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."roblox_to_connections"() RETURNS void
    LANGUAGE "plpgsql"
    AS $$declare
  i record;
begin
  for i in select * from public.roblox_links
  loop
    insert into public.user_connections (sub, type, user_id)
    values (i.target_id, 2, i.owner_id);
  end loop;
end;$$;

ALTER FUNCTION "public"."roblox_to_connections"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."send_mellow_server_action_log"() RETURNS trigger
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$DECLARE
  secret text;
  server public.mellow_servers%rowtype;
  payload jsonb;
  signature text;
BEGIN
  select * from public.mellow_servers into server where (logging_types & 1) = 1;

  if found then
    -- Get the webhook URL and secret from the vault
    SELECT decrypted_secret INTO secret FROM vault.decrypted_secrets WHERE name = 'MELLOW_INTERNAL_API_SECRET' LIMIT 1;

    -- Generate the payload
    payload = jsonb_build_object(
      'type', new.type,
      'author', (select row_to_json(row) from (select id, name, username from public.users where id = new.author_id limit 1) row),
      'server_id', new.server_id
    );

    -- Generate the signature
    signature = generate_absolutesolver_hmac(secret, payload::text);

    -- Send the webhook request
    perform net.http_post(
      url:='https://mellow-internal-api.hakumi.cafe/absolutesolver/supabase_webhooks/action_log',
      body:=payload,
      headers:=jsonb_build_object(
        'content-type', 'application/json',
        'absolutesolver', signature
      )
    );
  end if;
  
  RETURN new;
END;$$;

ALTER FUNCTION "public"."send_mellow_server_action_log"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."send_team_invited_notifications"() RETURNS trigger
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$begin
  insert into public.user_notifications (type, user_id, target_user_id, target_team_id)
    values (0, new.user_id, new.author_id, new.team_id);
  return new;
end;$$;

ALTER FUNCTION "public"."send_team_invited_notifications"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."send_team_join_notifications"() RETURNS trigger
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$declare
  i record;
begin
  for i in select user_id from public.team_members where team_id = new.team_id
  loop
    insert into public.user_notifications (type, user_id, target_user_id, target_team_id)
    values (4, i.user_id, new.user_id, new.team_id);
  end loop;
  return new;
end;$$;

ALTER FUNCTION "public"."send_team_join_notifications"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."send_team_leave_notifications"() RETURNS trigger
    LANGUAGE "plpgsql" SECURITY DEFINER
    AS $$declare
  i record;
begin
  for i in select user_id from public.team_members where team_id = old.team_id
  loop
    insert into public.user_notifications (type, user_id, target_user_id, target_team_id)
    values (5, i.user_id, old.user_id, old.team_id);
  end loop;
  return old;
end;$$;

ALTER FUNCTION "public"."send_team_leave_notifications"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."send_user_post_liked_notification"() RETURNS trigger
    LANGUAGE "plpgsql"
    AS $$declare
   user_id uuid; 
begin
  select user_author_id into user_id from public.profile_posts where id = new.post_id;
  insert into public.user_notifications (type, user_id, target_user_id, target_profile_post_id)
    values (6, user_id, new.user_id, new.post_id);
  return new;
end;$$;

ALTER FUNCTION "public"."send_user_post_liked_notification"() OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."website_get_user_mellow_servers"(target_user_id uuid) RETURNS TABLE(id text, name text, avatar_url text, owner_team_name text, owner_user_name text, owner_user_username text)
    LANGUAGE "sql"
    AS $$
  select
    server.id,
    server.name,
    server.avatar_url,
    owner_team.display_name owner_team_name,
    owner_user.name owner_user_name,
    owner_user.username owner_user_username
  from
    public.mellow_servers server
    left join public.teams owner_team on owner_team.id = server.owner_team_id
    left join public.users owner_user on owner_user.id = server.owner_user_id
  where mellow_server_accessible_by_user(target_user_id, owner_user_id, owner_team_id)
  order by
    server.name;
$$;

ALTER FUNCTION "public"."website_get_user_mellow_servers"(target_user_id uuid) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."website_get_user_mellow_servers2"(target_user_id uuid) RETURNS TABLE(id text, name text, avatar_url text)
    LANGUAGE "sql"
    AS $$select id, name, avatar_url from mellow_servers
where mellow_server_accessible_by_user(target_user_id, owner_user_id, owner_team_id)$$;

ALTER FUNCTION "public"."website_get_user_mellow_servers2"(target_user_id uuid) OWNER TO "postgres";

CREATE OR REPLACE FUNCTION "public"."website_get_user_mellow_servers3"(target_user_id uuid) RETURNS TABLE(id text, name text, avatar_url text, owner_team_name text, owner_user_name text, owner_user_username text)
    LANGUAGE "sql"
    AS $$
  select
    server.id,
    server.name,
    server.avatar_url,
    owner_team.display_name owner_team_name,
    owner_user.name owner_user_name,
    owner_user.username owner_user_username
  from
    public.mellow_servers server
    left join public.teams owner_team on owner_team.id = server.owner_team_id
    left join public.users owner_user on owner_user.id = server.owner_user_id
  where owner_user_id = target_user_id or (owner_team_id != null and exists(select 1 from team_members where user_id = target_user_id and team_id = owner_team_id))
  order by
    server.name;
$$;

ALTER FUNCTION "public"."website_get_user_mellow_servers3"(target_user_id uuid) OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";

CREATE TABLE IF NOT EXISTS "public"."application_authorisations" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "scopes" text[] NOT NULL,
    "user_id" uuid NOT NULL,
    "application_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."application_authorisations" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."applications" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "name" text NOT NULL,
    "owner_id" uuid NOT NULL,
    "creator_id" uuid,
    "avatar_url" text,
    "secret_key" text NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "summary" text,
    "redirect_uris" text[] DEFAULT '{}'::text[] NOT NULL
);

ALTER TABLE "public"."applications" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."hero_extension_version_files" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "url" text NOT NULL,
    "version_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."hero_extension_version_files" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."hero_extension_versions" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "name" text NOT NULL,
    "semver" text NOT NULL,
    "platforms" smallint DEFAULT '0'::smallint NOT NULL,
    "author_id" uuid,
    "extension_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."hero_extension_versions" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."hero_extensions" (
    "name" text NOT NULL,
    "display_name" text NOT NULL,
    "owner_id" uuid NOT NULL,
    "creator_id" uuid,
    "avatar_url" text,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "supported_platforms" smallint DEFAULT '0'::smallint NOT NULL,
    "flags" smallint DEFAULT '0'::smallint NOT NULL,
    "id" uuid DEFAULT gen_random_uuid() NOT NULL
);

ALTER TABLE "public"."hero_extensions" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."koko_experiences" (
    "id" bigint NOT NULL,
    "creator_id" uuid,
    "owner_team_id" uuid,
    "owner_user_id" uuid,
    "hakureality_config" jsonb DEFAULT '{}'::jsonb NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."koko_experiences" OWNER TO "postgres";

ALTER TABLE "public"."koko_experiences" ALTER COLUMN "id" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "public"."koko_experiences_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE IF NOT EXISTS "public"."mellow_bind_requirements" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "type" smallint NOT NULL,
    "data" text[] NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "bind_id" uuid NOT NULL
);

ALTER TABLE "public"."mellow_bind_requirements" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."mellow_binds" (
    "type" smallint NOT NULL,
    "creator_id" uuid NOT NULL,
    "server_id" text NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "name" text NOT NULL,
    "requirements_type" smallint DEFAULT '0'::smallint NOT NULL,
    "metadata" jsonb DEFAULT '{}'::jsonb NOT NULL
);

ALTER TABLE "public"."mellow_binds" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."mellow_server_audit_logs" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "type" text NOT NULL,
    "author_id" uuid NOT NULL,
    "server_id" text NOT NULL,
    "target_link_id" uuid,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "data" jsonb,
    "target_webhook_id" uuid
);

ALTER TABLE "public"."mellow_server_audit_logs" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."mellow_server_webhooks" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "events" bigint DEFAULT '0'::bigint NOT NULL,
    "enabled" boolean DEFAULT true NOT NULL,
    "server_id" text NOT NULL,
    "target_url" text NOT NULL,
    "creator_id" uuid,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "request_headers" jsonb DEFAULT '{}'::jsonb NOT NULL,
    "request_method" text DEFAULT 'POST'::text NOT NULL,
    "name" text DEFAULT 'home is whenever i''m with you ❤️'::text NOT NULL
);

ALTER TABLE "public"."mellow_server_webhooks" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."mellow_servers" (
    "id" text NOT NULL,
    "name" text NOT NULL,
    "avatar_url" text,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "default_nickname" text DEFAULT ''::text NOT NULL,
    "logging_channel_id" text,
    "logging_types" bigint DEFAULT '0'::bigint NOT NULL,
    "allow_forced_syncing" boolean DEFAULT true NOT NULL,
    "skip_onboarding_to" smallint,
    "owner_team_id" uuid,
    "owner_user_id" uuid,
    "creator_id" uuid,
    "api_key_created_at" timestamp with time zone
);

ALTER TABLE "public"."mellow_servers" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."mellow_user_server_connections" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_id" uuid NOT NULL,
    "server_id" text NOT NULL,
    "connection_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "last_used_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."mellow_user_server_connections" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."mellow_user_server_settings" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_id" uuid NOT NULL,
    "server_id" text NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."mellow_user_server_settings" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."mellow_user_server_used_connections" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "sub" text NOT NULL,
    "type" smallint NOT NULL,
    "user_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "last_used_at" timestamp with time zone DEFAULT now() NOT NULL,
    "server_id" text NOT NULL
);

ALTER TABLE "public"."mellow_user_server_used_connections" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."mellow_user_servers" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "data" jsonb NOT NULL,
    "user_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."mellow_user_servers" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."oauth_response_codes" (
    "id" text NOT NULL,
    "scopes" text[] DEFAULT '{}'::text[] NOT NULL,
    "user_id" uuid NOT NULL,
    "application_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."oauth_response_codes" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."profile_post_attachments" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "url" text NOT NULL,
    "post_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."profile_post_attachments" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."profile_post_likes" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_id" uuid NOT NULL,
    "post_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."profile_post_likes" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."profile_posts" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "content" text NOT NULL,
    "user_author_id" uuid,
    "team_author_id" uuid,
    "parent_post_id" uuid,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."profile_posts" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."team_affiliations" (
    "user_id" uuid,
    "team_id" uuid,
    "creator_id" uuid,
    "affiliator_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "id" uuid DEFAULT gen_random_uuid() NOT NULL
);

ALTER TABLE "public"."team_affiliations" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."team_audit_logs" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "type" text NOT NULL,
    "data" jsonb,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "team_id" uuid NOT NULL,
    "author_id" uuid,
    "target_role_id" uuid,
    "target_user_id" uuid,
    "target_mellow_server_id" text
);

ALTER TABLE "public"."team_audit_logs" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."team_invites" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_id" uuid NOT NULL,
    "team_id" uuid NOT NULL,
    "author_id" uuid,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."team_invites" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."team_members" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_id" uuid NOT NULL,
    "team_id" uuid NOT NULL,
    "joined_at" timestamp with time zone DEFAULT now() NOT NULL,
    "inviter_id" uuid,
    "role_id" uuid
);

ALTER TABLE "public"."team_members" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."team_roles" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "name" text NOT NULL,
    "position" smallint DEFAULT '0'::smallint NOT NULL,
    "team_id" uuid NOT NULL,
    "creator_id" uuid,
    "permissions" bigint DEFAULT '0'::bigint NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT "team_roles_position_check" CHECK (("position" >= 0))
);

ALTER TABLE "public"."team_roles" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."teams" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "name" text NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "display_name" text NOT NULL,
    "bio" text,
    "flags" smallint DEFAULT '0'::smallint NOT NULL,
    "avatar_url" text,
    "creator_id" uuid,
    "owner_id" uuid,
    "website_url" text
);

ALTER TABLE "public"."teams" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."user_connections" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "sub" text NOT NULL,
    "type" smallint NOT NULL,
    "user_id" uuid NOT NULL,
    "metadata" jsonb,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "avatar_url" text,
    "website_url" text,
    "display_name" text,
    "username" text
);

ALTER TABLE "public"."user_connections" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."user_devices" (
    "id" text NOT NULL,
    "user_id" uuid NOT NULL,
    "public_key" text NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "transports" text[] DEFAULT '{}'::text[] NOT NULL,
    "user_agent" text DEFAULT ''::text NOT NULL,
    "user_os" text DEFAULT ''::text NOT NULL,
    "user_platform" text DEFAULT ''::text NOT NULL,
    "name" text DEFAULT 'Default Sign-In Security Key'::text NOT NULL,
    "user_country" text,
    "last_used_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."user_devices" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."user_followers" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "target_user_id" uuid NOT NULL
);

ALTER TABLE "public"."user_followers" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."user_notices" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "type" smallint NOT NULL,
    "user_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."user_notices" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."user_notifications" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "type" smallint NOT NULL,
    "state" smallint DEFAULT '0'::smallint NOT NULL,
    "user_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "target_team_id" uuid,
    "target_user_id" uuid,
    "data" jsonb,
    "target_profile_post_id" uuid
);

ALTER TABLE "public"."user_notifications" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."user_recovery_links" (
    "id" text NOT NULL,
    "user_id" uuid NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE "public"."user_recovery_links" OWNER TO "postgres";

CREATE TABLE IF NOT EXISTS "public"."users" (
    "id" uuid DEFAULT gen_random_uuid() NOT NULL,
    "name" text,
    "username" text NOT NULL,
    "created_at" timestamp with time zone DEFAULT now() NOT NULL,
    "bio" text,
    "flags" smallint DEFAULT '0'::smallint NOT NULL,
    "avatar_url" text,
    "internal_id" bigint NOT NULL,
    "is_edited" boolean DEFAULT false NOT NULL,
    "sudo_mode_last_entered_at" timestamp with time zone DEFAULT now() NOT NULL,
    "mellow_pending_signup" boolean DEFAULT false NOT NULL,
    CONSTRAINT "users_bio_check" CHECK ((length(bio) < 200))
);

ALTER TABLE "public"."users" OWNER TO "postgres";

ALTER TABLE "public"."users" ALTER COLUMN "internal_id" ADD GENERATED BY DEFAULT AS IDENTITY (
    SEQUENCE NAME "public"."users_internal_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

CREATE TABLE IF NOT EXISTS "supabase_migrations"."schema_migrations" (
    "version" text NOT NULL
);

ALTER TABLE "supabase_migrations"."schema_migrations" OWNER TO "postgres";

ALTER TABLE ONLY "public"."application_authorisations"
    ADD CONSTRAINT "application_authorisations_id_key" UNIQUE ("id");

ALTER TABLE ONLY "public"."application_authorisations"
    ADD CONSTRAINT "application_authorisations_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."hero_extension_version_files"
    ADD CONSTRAINT "hero_extension_version_files_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."hero_extension_versions"
    ADD CONSTRAINT "hero_extension_versions_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."hero_extensions"
    ADD CONSTRAINT "hero_extensions_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."koko_experiences"
    ADD CONSTRAINT "koko_experiences_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_bind_requirements"
    ADD CONSTRAINT "mellow_bind_requirements_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_binds"
    ADD CONSTRAINT "mellow_binds_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_server_audit_logs"
    ADD CONSTRAINT "mellow_server_audit_logs_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_server_webhooks"
    ADD CONSTRAINT "mellow_server_webhooks_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_servers"
    ADD CONSTRAINT "mellow_servers_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_user_server_connections"
    ADD CONSTRAINT "mellow_user_server_connections_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_user_server_settings"
    ADD CONSTRAINT "mellow_user_server_settings_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_user_server_used_connections"
    ADD CONSTRAINT "mellow_user_server_used_connections_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_user_servers"
    ADD CONSTRAINT "mellow_user_servers_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."mellow_user_servers"
    ADD CONSTRAINT "mellow_user_servers_user_id_key" UNIQUE ("user_id");

ALTER TABLE ONLY "public"."applications"
    ADD CONSTRAINT "oauth_applications_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."oauth_response_codes"
    ADD CONSTRAINT "oauth_response_codes_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."profile_post_attachments"
    ADD CONSTRAINT "profile_post_attachments_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."profile_post_likes"
    ADD CONSTRAINT "profile_post_likes_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."profile_posts"
    ADD CONSTRAINT "profile_posts_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."team_affiliations"
    ADD CONSTRAINT "team_affiliations_id_key" UNIQUE ("id");

ALTER TABLE ONLY "public"."team_affiliations"
    ADD CONSTRAINT "team_affiliations_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."team_audit_logs"
    ADD CONSTRAINT "team_audit_logs_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."team_invites"
    ADD CONSTRAINT "team_invites_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."team_roles"
    ADD CONSTRAINT "team_roles_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_name_key" UNIQUE ("name");

ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."user_connections"
    ADD CONSTRAINT "user_connections_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."user_devices"
    ADD CONSTRAINT "user_devices_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."user_followers"
    ADD CONSTRAINT "user_followers_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."user_notices"
    ADD CONSTRAINT "user_notices_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."user_notifications"
    ADD CONSTRAINT "user_notifications_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."user_recovery_links"
    ADD CONSTRAINT "user_recovery_links_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_internal_id_key" UNIQUE ("internal_id");

ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_pkey" PRIMARY KEY ("id");

ALTER TABLE ONLY "public"."users"
    ADD CONSTRAINT "users_username_key" UNIQUE ("username");

ALTER TABLE ONLY "supabase_migrations"."schema_migrations"
    ADD CONSTRAINT "schema_migrations_pkey" PRIMARY KEY ("version");

CREATE INDEX idx_user_id ON public.users USING brin (id);

CREATE TRIGGER send_mellow_server_action_logs AFTER INSERT ON public.mellow_server_audit_logs FOR EACH ROW EXECUTE FUNCTION public.send_mellow_server_action_log();

CREATE TRIGGER send_team_invited_notifications AFTER INSERT ON public.team_invites FOR EACH ROW EXECUTE FUNCTION public.send_team_invited_notifications();

CREATE TRIGGER send_team_join_notifications BEFORE INSERT ON public.team_members FOR EACH ROW EXECUTE FUNCTION public.send_team_join_notifications();

CREATE TRIGGER send_team_leave_notifications AFTER DELETE ON public.team_members FOR EACH ROW EXECUTE FUNCTION public.send_team_leave_notifications();

CREATE TRIGGER send_user_post_liked_notification AFTER INSERT ON public.profile_post_likes FOR EACH ROW EXECUTE FUNCTION public.send_user_post_liked_notification();

ALTER TABLE ONLY "public"."application_authorisations"
    ADD CONSTRAINT "application_authorisations_application_id_fkey" FOREIGN KEY (application_id) REFERENCES public.applications(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."application_authorisations"
    ADD CONSTRAINT "application_authorisations_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."applications"
    ADD CONSTRAINT "applications_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id);

ALTER TABLE ONLY "public"."applications"
    ADD CONSTRAINT "applications_owner_id_fkey" FOREIGN KEY (owner_id) REFERENCES public.teams(id) ON UPDATE CASCADE;

ALTER TABLE ONLY "public"."hero_extension_version_files"
    ADD CONSTRAINT "hero_extension_version_files_version_id_fkey" FOREIGN KEY (version_id) REFERENCES public.hero_extension_versions(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."hero_extension_versions"
    ADD CONSTRAINT "hero_extension_versions_author_id_fkey" FOREIGN KEY (author_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET DEFAULT;

ALTER TABLE ONLY "public"."hero_extension_versions"
    ADD CONSTRAINT "hero_extension_versions_extension_id_fkey" FOREIGN KEY (extension_id) REFERENCES public.hero_extensions(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."hero_extensions"
    ADD CONSTRAINT "hero_extensions_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET DEFAULT;

ALTER TABLE ONLY "public"."hero_extensions"
    ADD CONSTRAINT "hero_extensions_owner_id_fkey" FOREIGN KEY (owner_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."koko_experiences"
    ADD CONSTRAINT "koko_experiences_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;

ALTER TABLE ONLY "public"."koko_experiences"
    ADD CONSTRAINT "koko_experiences_owner_team_id_fkey" FOREIGN KEY (owner_team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."koko_experiences"
    ADD CONSTRAINT "koko_experiences_owner_user_id_fkey" FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_bind_requirements"
    ADD CONSTRAINT "mellow_bind_requirements_bind_id_fkey" FOREIGN KEY (bind_id) REFERENCES public.mellow_binds(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_binds"
    ADD CONSTRAINT "mellow_binds_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_binds"
    ADD CONSTRAINT "mellow_binds_server_id_fkey" FOREIGN KEY (server_id) REFERENCES public.mellow_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_server_audit_logs"
    ADD CONSTRAINT "mellow_server_audit_logs_author_id_fkey" FOREIGN KEY (author_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_server_audit_logs"
    ADD CONSTRAINT "mellow_server_audit_logs_server_id_fkey" FOREIGN KEY (server_id) REFERENCES public.mellow_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_server_audit_logs"
    ADD CONSTRAINT "mellow_server_audit_logs_target_link_id_fkey" FOREIGN KEY (target_link_id) REFERENCES public.mellow_binds(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."mellow_server_audit_logs"
    ADD CONSTRAINT "mellow_server_audit_logs_target_webhook_id_fkey" FOREIGN KEY (target_webhook_id) REFERENCES public.mellow_server_webhooks(id) ON UPDATE CASCADE ON DELETE SET NULL;

ALTER TABLE ONLY "public"."mellow_server_webhooks"
    ADD CONSTRAINT "mellow_server_webhooks_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."mellow_server_webhooks"
    ADD CONSTRAINT "mellow_server_webhooks_server_id_fkey" FOREIGN KEY (server_id) REFERENCES public.mellow_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_servers"
    ADD CONSTRAINT "mellow_servers_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;

ALTER TABLE ONLY "public"."mellow_servers"
    ADD CONSTRAINT "mellow_servers_owner_team_id_fkey" FOREIGN KEY (owner_team_id) REFERENCES public.teams(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_servers"
    ADD CONSTRAINT "mellow_servers_owner_user_id_fkey" FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_user_server_connections"
    ADD CONSTRAINT "mellow_user_server_connections_connection_id_fkey" FOREIGN KEY (connection_id) REFERENCES public.user_connections(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_user_server_connections"
    ADD CONSTRAINT "mellow_user_server_connections_server_id_fkey" FOREIGN KEY (server_id) REFERENCES public.mellow_servers(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_user_server_connections"
    ADD CONSTRAINT "mellow_user_server_connections_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_user_server_settings"
    ADD CONSTRAINT "mellow_user_server_settings_server_id_fkey" FOREIGN KEY (server_id) REFERENCES public.mellow_servers(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_user_server_settings"
    ADD CONSTRAINT "mellow_user_server_settings_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_user_server_used_connections"
    ADD CONSTRAINT "mellow_user_server_used_connections_server_id_fkey" FOREIGN KEY (server_id) REFERENCES public.mellow_servers(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_user_server_used_connections"
    ADD CONSTRAINT "mellow_user_server_used_connections_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."mellow_user_servers"
    ADD CONSTRAINT "mellow_user_servers_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."oauth_response_codes"
    ADD CONSTRAINT "oauth_response_codes_application_id_fkey" FOREIGN KEY (application_id) REFERENCES public.applications(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."oauth_response_codes"
    ADD CONSTRAINT "oauth_response_codes_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."profile_post_attachments"
    ADD CONSTRAINT "profile_post_attachments_post_id_fkey" FOREIGN KEY (post_id) REFERENCES public.profile_posts(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."profile_post_likes"
    ADD CONSTRAINT "profile_post_likes_post_id_fkey" FOREIGN KEY (post_id) REFERENCES public.profile_posts(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."profile_post_likes"
    ADD CONSTRAINT "profile_post_likes_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."profile_posts"
    ADD CONSTRAINT "profile_posts_parent_post_id_fkey" FOREIGN KEY (parent_post_id) REFERENCES public.profile_posts(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."profile_posts"
    ADD CONSTRAINT "profile_posts_team_author_id_fkey" FOREIGN KEY (team_author_id) REFERENCES public.teams(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."profile_posts"
    ADD CONSTRAINT "profile_posts_user_author_id_fkey" FOREIGN KEY (user_author_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_affiliations"
    ADD CONSTRAINT "team_affiliations_affiliator_id_fkey" FOREIGN KEY (affiliator_id) REFERENCES public.teams(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_affiliations"
    ADD CONSTRAINT "team_affiliations_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."team_affiliations"
    ADD CONSTRAINT "team_affiliations_team_id_fkey" FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_affiliations"
    ADD CONSTRAINT "team_affiliations_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_audit_logs"
    ADD CONSTRAINT "team_audit_logs_author_id_fkey" FOREIGN KEY (author_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_audit_logs"
    ADD CONSTRAINT "team_audit_logs_target_mellow_server_id_fkey" FOREIGN KEY (target_mellow_server_id) REFERENCES public.mellow_servers(id) ON UPDATE CASCADE ON DELETE SET DEFAULT;

ALTER TABLE ONLY "public"."team_audit_logs"
    ADD CONSTRAINT "team_audit_logs_target_role_id_fkey" FOREIGN KEY (target_role_id) REFERENCES public.team_roles(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."team_audit_logs"
    ADD CONSTRAINT "team_audit_logs_target_user_id_fkey" FOREIGN KEY (target_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."team_audit_logs"
    ADD CONSTRAINT "team_audit_logs_team_id_fkey" FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_invites"
    ADD CONSTRAINT "team_invites_author_id_fkey" FOREIGN KEY (author_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."team_invites"
    ADD CONSTRAINT "team_invites_team_id_fkey" FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_invites"
    ADD CONSTRAINT "team_invites_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_inviter_id_fkey" FOREIGN KEY (inviter_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_role_id_fkey" FOREIGN KEY (role_id) REFERENCES public.team_roles(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_team_id_fkey" FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_members"
    ADD CONSTRAINT "team_members_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."team_roles"
    ADD CONSTRAINT "team_roles_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."team_roles"
    ADD CONSTRAINT "team_roles_team_id_fkey" FOREIGN KEY (team_id) REFERENCES public.teams(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_creator_id_fkey" FOREIGN KEY (creator_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."teams"
    ADD CONSTRAINT "teams_owner_id_fkey" FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY "public"."user_connections"
    ADD CONSTRAINT "user_connections_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_devices"
    ADD CONSTRAINT "user_devices_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_followers"
    ADD CONSTRAINT "user_followers_target_user_id_fkey" FOREIGN KEY (target_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_followers"
    ADD CONSTRAINT "user_followers_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_notices"
    ADD CONSTRAINT "user_notices_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_notifications"
    ADD CONSTRAINT "user_notifications_target_profile_post_id_fkey" FOREIGN KEY (target_profile_post_id) REFERENCES public.profile_posts(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_notifications"
    ADD CONSTRAINT "user_notifications_target_team_id_fkey" FOREIGN KEY (target_team_id) REFERENCES public.teams(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_notifications"
    ADD CONSTRAINT "user_notifications_target_user_id_fkey" FOREIGN KEY (target_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_notifications"
    ADD CONSTRAINT "user_notifications_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY "public"."user_recovery_links"
    ADD CONSTRAINT "user_recovery_links_user_id_fkey" FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE "public"."application_authorisations" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."applications" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."hero_extension_version_files" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."hero_extension_versions" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."hero_extensions" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."koko_experiences" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_bind_requirements" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_binds" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_server_audit_logs" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_server_webhooks" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_servers" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_user_server_connections" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_user_server_settings" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_user_server_used_connections" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."mellow_user_servers" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."oauth_response_codes" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."profile_post_attachments" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."profile_post_likes" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."profile_posts" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."team_affiliations" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."team_audit_logs" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."team_invites" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."team_members" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."team_roles" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."teams" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."user_connections" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."user_devices" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."user_followers" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."user_notices" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."user_notifications" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."user_recovery_links" ENABLE ROW LEVEL SECURITY;

ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;

REVOKE USAGE ON SCHEMA "public" FROM PUBLIC;
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";

GRANT ALL ON FUNCTION "public"."add_mellow_user_server_used_connection"(sub text, type smallint, user_id uuid) TO "anon";
GRANT ALL ON FUNCTION "public"."add_mellow_user_server_used_connection"(sub text, type smallint, user_id uuid) TO "authenticated";
GRANT ALL ON FUNCTION "public"."add_mellow_user_server_used_connection"(sub text, type smallint, user_id uuid) TO "service_role";

GRANT ALL ON FUNCTION "public"."add_mellow_user_server_used_connection2"(sub text, type smallint, user_id uuid, server_id text) TO "anon";
GRANT ALL ON FUNCTION "public"."add_mellow_user_server_used_connection2"(sub text, type smallint, user_id uuid, server_id text) TO "authenticated";
GRANT ALL ON FUNCTION "public"."add_mellow_user_server_used_connection2"(sub text, type smallint, user_id uuid, server_id text) TO "service_role";

GRANT ALL ON FUNCTION "public"."auth_to_connections"() TO "anon";
GRANT ALL ON FUNCTION "public"."auth_to_connections"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."auth_to_connections"() TO "service_role";

GRANT ALL ON FUNCTION "public"."create_new_user_profile"() TO "anon";
GRANT ALL ON FUNCTION "public"."create_new_user_profile"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_new_user_profile"() TO "service_role";

GRANT ALL ON FUNCTION "public"."generate_absolutesolver_hmac"(secret text, message text) TO "anon";
GRANT ALL ON FUNCTION "public"."generate_absolutesolver_hmac"(secret text, message text) TO "authenticated";
GRANT ALL ON FUNCTION "public"."generate_absolutesolver_hmac"(secret text, message text) TO "service_role";

GRANT ALL ON FUNCTION "public"."get_relevant_discord_server_links"(server_id text) TO "anon";
GRANT ALL ON FUNCTION "public"."get_relevant_discord_server_links"(server_id text) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_relevant_discord_server_links"(server_id text) TO "service_role";

GRANT ALL ON FUNCTION "public"."get_user_by_discord_user_id"(discord_user_id text) TO "anon";
GRANT ALL ON FUNCTION "public"."get_user_by_discord_user_id"(discord_user_id text) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_user_by_discord_user_id"(discord_user_id text) TO "service_role";

GRANT ALL ON FUNCTION "public"."mellow_server_accessible_by_user"(target_user_id uuid, owner_user_id uuid, owner_team_id uuid) TO "anon";
GRANT ALL ON FUNCTION "public"."mellow_server_accessible_by_user"(target_user_id uuid, owner_user_id uuid, owner_team_id uuid) TO "authenticated";
GRANT ALL ON FUNCTION "public"."mellow_server_accessible_by_user"(target_user_id uuid, owner_user_id uuid, owner_team_id uuid) TO "service_role";

GRANT ALL ON FUNCTION "public"."mellow_server_accessible_by_user2"(server_id text, user_id uuid) TO "anon";
GRANT ALL ON FUNCTION "public"."mellow_server_accessible_by_user2"(server_id text, user_id uuid) TO "authenticated";
GRANT ALL ON FUNCTION "public"."mellow_server_accessible_by_user2"(server_id text, user_id uuid) TO "service_role";

GRANT ALL ON FUNCTION "public"."mellow_to_connections"() TO "anon";
GRANT ALL ON FUNCTION "public"."mellow_to_connections"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."mellow_to_connections"() TO "service_role";

GRANT ALL ON FUNCTION "public"."roblox_to_connections"() TO "anon";
GRANT ALL ON FUNCTION "public"."roblox_to_connections"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."roblox_to_connections"() TO "service_role";

GRANT ALL ON FUNCTION "public"."send_mellow_server_action_log"() TO "anon";
GRANT ALL ON FUNCTION "public"."send_mellow_server_action_log"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."send_mellow_server_action_log"() TO "service_role";

GRANT ALL ON FUNCTION "public"."send_team_invited_notifications"() TO "anon";
GRANT ALL ON FUNCTION "public"."send_team_invited_notifications"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."send_team_invited_notifications"() TO "service_role";

GRANT ALL ON FUNCTION "public"."send_team_join_notifications"() TO "anon";
GRANT ALL ON FUNCTION "public"."send_team_join_notifications"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."send_team_join_notifications"() TO "service_role";

GRANT ALL ON FUNCTION "public"."send_team_leave_notifications"() TO "anon";
GRANT ALL ON FUNCTION "public"."send_team_leave_notifications"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."send_team_leave_notifications"() TO "service_role";

GRANT ALL ON FUNCTION "public"."send_user_post_liked_notification"() TO "anon";
GRANT ALL ON FUNCTION "public"."send_user_post_liked_notification"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."send_user_post_liked_notification"() TO "service_role";

GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers"(target_user_id uuid) TO "anon";
GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers"(target_user_id uuid) TO "authenticated";
GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers"(target_user_id uuid) TO "service_role";

GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers2"(target_user_id uuid) TO "anon";
GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers2"(target_user_id uuid) TO "authenticated";
GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers2"(target_user_id uuid) TO "service_role";

GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers3"(target_user_id uuid) TO "anon";
GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers3"(target_user_id uuid) TO "authenticated";
GRANT ALL ON FUNCTION "public"."website_get_user_mellow_servers3"(target_user_id uuid) TO "service_role";

GRANT ALL ON TABLE "public"."application_authorisations" TO "anon";
GRANT ALL ON TABLE "public"."application_authorisations" TO "authenticated";
GRANT ALL ON TABLE "public"."application_authorisations" TO "service_role";

GRANT ALL ON TABLE "public"."applications" TO "anon";
GRANT ALL ON TABLE "public"."applications" TO "authenticated";
GRANT ALL ON TABLE "public"."applications" TO "service_role";

GRANT ALL ON TABLE "public"."hero_extension_version_files" TO "anon";
GRANT ALL ON TABLE "public"."hero_extension_version_files" TO "authenticated";
GRANT ALL ON TABLE "public"."hero_extension_version_files" TO "service_role";

GRANT ALL ON TABLE "public"."hero_extension_versions" TO "anon";
GRANT ALL ON TABLE "public"."hero_extension_versions" TO "authenticated";
GRANT ALL ON TABLE "public"."hero_extension_versions" TO "service_role";

GRANT ALL ON TABLE "public"."hero_extensions" TO "anon";
GRANT ALL ON TABLE "public"."hero_extensions" TO "authenticated";
GRANT ALL ON TABLE "public"."hero_extensions" TO "service_role";

GRANT ALL ON TABLE "public"."koko_experiences" TO "anon";
GRANT ALL ON TABLE "public"."koko_experiences" TO "authenticated";
GRANT ALL ON TABLE "public"."koko_experiences" TO "service_role";

GRANT ALL ON SEQUENCE "public"."koko_experiences_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."koko_experiences_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."koko_experiences_id_seq" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_bind_requirements" TO "anon";
GRANT ALL ON TABLE "public"."mellow_bind_requirements" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_bind_requirements" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_binds" TO "anon";
GRANT ALL ON TABLE "public"."mellow_binds" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_binds" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_server_audit_logs" TO "anon";
GRANT ALL ON TABLE "public"."mellow_server_audit_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_server_audit_logs" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_server_webhooks" TO "anon";
GRANT ALL ON TABLE "public"."mellow_server_webhooks" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_server_webhooks" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_servers" TO "anon";
GRANT ALL ON TABLE "public"."mellow_servers" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_servers" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_user_server_connections" TO "anon";
GRANT ALL ON TABLE "public"."mellow_user_server_connections" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_user_server_connections" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_user_server_settings" TO "anon";
GRANT ALL ON TABLE "public"."mellow_user_server_settings" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_user_server_settings" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_user_server_used_connections" TO "anon";
GRANT ALL ON TABLE "public"."mellow_user_server_used_connections" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_user_server_used_connections" TO "service_role";

GRANT ALL ON TABLE "public"."mellow_user_servers" TO "anon";
GRANT ALL ON TABLE "public"."mellow_user_servers" TO "authenticated";
GRANT ALL ON TABLE "public"."mellow_user_servers" TO "service_role";

GRANT ALL ON TABLE "public"."oauth_response_codes" TO "anon";
GRANT ALL ON TABLE "public"."oauth_response_codes" TO "authenticated";
GRANT ALL ON TABLE "public"."oauth_response_codes" TO "service_role";

GRANT ALL ON TABLE "public"."profile_post_attachments" TO "anon";
GRANT ALL ON TABLE "public"."profile_post_attachments" TO "authenticated";
GRANT ALL ON TABLE "public"."profile_post_attachments" TO "service_role";

GRANT ALL ON TABLE "public"."profile_post_likes" TO "anon";
GRANT ALL ON TABLE "public"."profile_post_likes" TO "authenticated";
GRANT ALL ON TABLE "public"."profile_post_likes" TO "service_role";

GRANT ALL ON TABLE "public"."profile_posts" TO "anon";
GRANT ALL ON TABLE "public"."profile_posts" TO "authenticated";
GRANT ALL ON TABLE "public"."profile_posts" TO "service_role";

GRANT ALL ON TABLE "public"."team_affiliations" TO "anon";
GRANT ALL ON TABLE "public"."team_affiliations" TO "authenticated";
GRANT ALL ON TABLE "public"."team_affiliations" TO "service_role";

GRANT ALL ON TABLE "public"."team_audit_logs" TO "anon";
GRANT ALL ON TABLE "public"."team_audit_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."team_audit_logs" TO "service_role";

GRANT ALL ON TABLE "public"."team_invites" TO "anon";
GRANT ALL ON TABLE "public"."team_invites" TO "authenticated";
GRANT ALL ON TABLE "public"."team_invites" TO "service_role";

GRANT ALL ON TABLE "public"."team_members" TO "anon";
GRANT ALL ON TABLE "public"."team_members" TO "authenticated";
GRANT ALL ON TABLE "public"."team_members" TO "service_role";

GRANT ALL ON TABLE "public"."team_roles" TO "anon";
GRANT ALL ON TABLE "public"."team_roles" TO "authenticated";
GRANT ALL ON TABLE "public"."team_roles" TO "service_role";

GRANT ALL ON TABLE "public"."teams" TO "anon";
GRANT ALL ON TABLE "public"."teams" TO "authenticated";
GRANT ALL ON TABLE "public"."teams" TO "service_role";

GRANT ALL ON TABLE "public"."user_connections" TO "anon";
GRANT ALL ON TABLE "public"."user_connections" TO "authenticated";
GRANT ALL ON TABLE "public"."user_connections" TO "service_role";

GRANT ALL ON TABLE "public"."user_devices" TO "anon";
GRANT ALL ON TABLE "public"."user_devices" TO "authenticated";
GRANT ALL ON TABLE "public"."user_devices" TO "service_role";

GRANT ALL ON TABLE "public"."user_followers" TO "anon";
GRANT ALL ON TABLE "public"."user_followers" TO "authenticated";
GRANT ALL ON TABLE "public"."user_followers" TO "service_role";

GRANT ALL ON TABLE "public"."user_notices" TO "anon";
GRANT ALL ON TABLE "public"."user_notices" TO "authenticated";
GRANT ALL ON TABLE "public"."user_notices" TO "service_role";

GRANT ALL ON TABLE "public"."user_notifications" TO "anon";
GRANT ALL ON TABLE "public"."user_notifications" TO "authenticated";
GRANT ALL ON TABLE "public"."user_notifications" TO "service_role";

GRANT ALL ON TABLE "public"."user_recovery_links" TO "anon";
GRANT ALL ON TABLE "public"."user_recovery_links" TO "authenticated";
GRANT ALL ON TABLE "public"."user_recovery_links" TO "service_role";

GRANT ALL ON TABLE "public"."users" TO "anon";
GRANT ALL ON TABLE "public"."users" TO "authenticated";
GRANT ALL ON TABLE "public"."users" TO "service_role";

GRANT ALL ON SEQUENCE "public"."users_internal_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."users_internal_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."users_internal_id_seq" TO "service_role";

ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES  TO "service_role";

ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS  TO "service_role";

ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES  TO "service_role";

RESET ALL;
