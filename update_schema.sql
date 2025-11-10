-- Step 1: Drop existing objects in a clean order to avoid dependency errors.
DROP FUNCTION IF EXISTS public.handle_new_user() CASCADE;
DROP FUNCTION IF EXISTS public.get_all_communities(uuid) CASCADE;
DROP FUNCTION IF EXISTS public.get_joined_communities(uuid) CASCADE;
DROP FUNCTION IF EXISTS public.get_hosted_communities(uuid) CASCADE;
DROP FUNCTION IF EXISTS public.get_community_details(uuid, uuid) CASCADE;
DROP FUNCTION IF EXISTS public.get_polls_for_community(uuid, uuid) CASCADE;
DROP FUNCTION IF EXISTS public.get_poll_results(uuid) CASCADE;
DROP FUNCTION IF EXISTS public.get_upcoming_events() CASCADE;
DROP FUNCTION IF EXISTS public.delete_event_and_storage(uuid, uuid) CASCADE;
DROP FUNCTION IF EXISTS public.delete_past_events() CASCADE;
DROP FUNCTION IF EXISTS public.cleanup_orphaned_images() CASCADE;

-- Unschedule any existing cron job to avoid errors
SELECT cron.unschedule('daily-orphan-cleanup') FROM (SELECT 1) AS t(c) WHERE EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'daily-orphan-cleanup');


DROP TABLE IF EXISTS public.poll_votes;
DROP TABLE IF EXISTS public.poll_options;
DROP TABLE IF EXISTS public.polls;
DROP TABLE IF EXISTS public.messages;
DROP TABLE IF EXISTS public.memberships;
DROP TABLE IF EXISTS public.events;
DROP TABLE IF EXISTS public.communities;
DROP TABLE IF EXISTS public.users;

-- Step 2: Enable necessary extensions.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_cron";

-- Step 3: Re-create all tables with the new schema.

-- Users Table: Stores user profile information.
CREATE TABLE public.users (
    id UUID PRIMARY KEY NOT NULL,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE,
    avatar TEXT,
    description TEXT,
    timezone TEXT DEFAULT 'UTC' NOT NULL, -- Added timezone column
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    CONSTRAINT fk_auth_users FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE public.users IS 'Stores public user profile information, linked to Supabase auth.';

-- Events Table: Stores event details with soft delete support.
CREATE TABLE public.events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    creator_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    event_name TEXT NOT NULL,
    host_name TEXT NOT NULL,
    host_email TEXT NOT NULL,
    venue TEXT NOT NULL,
    agenda TEXT,
    event_datetime TIMESTAMPTZ NOT NULL, -- Replaced date and time with a single timestamptz column
    category TEXT,
    registration_link TEXT,
    event_logo TEXT,
    hero_text_line1 TEXT,
    hero_text_line2 TEXT,
    parallax_img_1 TEXT,
    parallax_img_2 TEXT,
    parallax_img_3 TEXT,
    how_we_planned_text TEXT,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    deleted_at TIMESTAMPTZ -- New column for soft deletes
);
COMMENT ON TABLE public.events IS 'Stores details for events. Soft deletes are handled via the `deleted_at` column.';

-- Communities Table: Stores community/group information.
CREATE TABLE public.communities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    creator_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    description TEXT,
    visibility TEXT DEFAULT 'public' NOT NULL,
    join_code TEXT UNIQUE,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);
COMMENT ON TABLE public.communities IS 'Stores chat communities or groups.';

-- Memberships Table: Links users to communities.
CREATE TABLE public.memberships (
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE NOT NULL,
    community_id UUID REFERENCES public.communities(id) ON DELETE CASCADE NOT NULL,
    is_admin BOOLEAN DEFAULT FALSE NOT NULL,
    joined_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    PRIMARY KEY (user_id, community_id)
);
COMMENT ON TABLE public.memberships IS 'Tracks which users are members of which communities.';

-- Messages Table: Stores chat messages.
CREATE TABLE public.messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE NOT NULL,
    community_id UUID REFERENCES public.communities(id) ON DELETE CASCADE NOT NULL,
    text TEXT NOT NULL,
    reply_to_id UUID REFERENCES public.messages(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMPTZ
);
COMMENT ON TABLE public.messages IS 'Contains all chat messages for all communities.';

-- Polls Table: Stores poll questions.
CREATE TABLE public.polls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE NOT NULL,
    community_id UUID REFERENCES public.communities(id) ON DELETE CASCADE NOT NULL,
    question TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL
);
COMMENT ON TABLE public.polls IS 'Stores poll questions created within communities.';

-- Poll Options Table: Stores the options for each poll.
CREATE TABLE public.poll_options (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    poll_id UUID REFERENCES public.polls(id) ON DELETE CASCADE NOT NULL,
    option_text TEXT NOT NULL
);
COMMENT ON TABLE public.poll_options IS 'Stores the choices for a given poll.';

-- Poll Votes Table: Records user votes on polls.
CREATE TABLE public.poll_votes (
    user_id UUID REFERENCES public.users(id) ON DELETE CASCADE NOT NULL,
    poll_id UUID REFERENCES public.polls(id) ON DELETE CASCADE NOT NULL,
    option_id UUID REFERENCES public.poll_options(id) ON DELETE CASCADE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT timezone('utc'::text, now()) NOT NULL,
    PRIMARY KEY (user_id, poll_id)
);
COMMENT ON TABLE public.poll_votes IS 'Records which user voted for which option in a poll.';


-- Step 4: Create a trigger to automatically copy new users from auth.users to public.users.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.users (id, email)
    VALUES (new.id, new.email);
    RETURN new;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE PROCEDURE public.handle_new_user();

COMMENT ON FUNCTION public.handle_new_user() IS 'Automatically creates a public user profile when a new user signs up.';


-- Step 5: Re-create all the helper functions (RPCs) with necessary modifications.

-- Function to get upcoming events, now filtering out soft-deleted ones.
CREATE OR REPLACE FUNCTION get_upcoming_events()
RETURNS SETOF events AS $$
BEGIN
    RETURN QUERY
    SELECT *
    FROM public.events
    WHERE
        deleted_at IS NULL -- Exclude soft-deleted events
        AND event_datetime >= now() -- Compare directly with the current UTC time
    ORDER BY event_datetime ASC;
END;
$$ LANGUAGE plpgsql;
COMMENT ON FUNCTION public.get_upcoming_events() IS 'Retrieves all non-deleted, upcoming events.';

-- Function to "delete" an event by marking it as deleted (soft delete).
CREATE OR REPLACE FUNCTION public.delete_event_and_storage(
    p_event_id UUID,
    p_user_id UUID DEFAULT NULL -- NULL for system-triggered deletions
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    event_record RECORD;
BEGIN
    RAISE LOG 'Attempting to soft delete event ID: % by user ID: %', p_event_id, p_user_id;

    SELECT id, creator_id INTO event_record
    FROM public.events
    WHERE id = p_event_id;

    IF event_record.id IS NULL THEN
        RAISE EXCEPTION 'Event with ID % not found.', p_event_id;
    END IF;

    IF p_user_id IS NOT NULL AND event_record.creator_id IS DISTINCT FROM p_user_id THEN
        RAISE EXCEPTION 'User % does not have permission to delete event %.', p_user_id, p_event_id;
    END IF;

    -- Perform the soft delete by updating the deleted_at timestamp
    UPDATE public.events
    SET deleted_at = timezone('utc'::text, now())
    WHERE id = p_event_id;

    RAISE LOG 'Soft-deleted event record ID: %', p_event_id;

EXCEPTION
    WHEN OTHERS THEN
        RAISE LOG 'Error in delete_event_and_storage for event %: %', p_event_id, SQLERRM;
        RAISE;
END;
$$;
COMMENT ON FUNCTION public.delete_event_and_storage(uuid, uuid) IS 'Performs a soft delete on an event by setting its `deleted_at` timestamp. Does not remove storage files.';

-- Function to soft-delete past events.
CREATE OR REPLACE FUNCTION public.delete_past_events()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RAISE LOG 'Starting scheduled job to soft-delete past events.';
  -- This function now simply compares the event's UTC timestamp
  -- with the current UTC timestamp.
  UPDATE public.events
  SET deleted_at = NOW()
  WHERE event_datetime < NOW() AND deleted_at IS NULL;
  RAISE LOG 'Finished scheduled job to soft-delete past events.';
END;
$$;
COMMENT ON FUNCTION public.delete_past_events() IS 'Scheduled job to soft-delete events that have already occurred.';

-- Function to clean up orphaned image files from storage.
CREATE OR REPLACE FUNCTION cleanup_orphaned_images()
RETURNS VOID AS $$
DECLARE
    all_files TEXT[];
    used_files TEXT[];
    orphaned_files TEXT[];
    bucket_name TEXT := 'event-images';
BEGIN
    SET search_path = public, storage;

    SELECT array_agg(name) INTO all_files FROM storage.objects WHERE bucket_id = bucket_name;

    IF all_files IS NULL THEN
        RAISE LOG 'No files found in bucket %. Exiting.', bucket_name;
        RETURN;
    END IF;

    -- Extract filenames from all non-null image URL columns in the events table
    SELECT array_agg(DISTINCT (string_to_array(image_url, '/'))[array_length(string_to_array(image_url, '/'), 1)])
    INTO used_files
    FROM (
        SELECT event_logo AS image_url FROM events WHERE event_logo IS NOT NULL
        UNION ALL SELECT parallax_img_1 FROM events WHERE parallax_img_1 IS NOT NULL
        UNION ALL SELECT parallax_img_2 FROM events WHERE parallax_img_2 IS NOT NULL
        UNION ALL SELECT parallax_img_3 FROM events WHERE parallax_img_3 IS NOT NULL
    ) AS used_images;

    used_files := COALESCE(used_files, ARRAY[]::TEXT[]);

    -- Find files that exist in storage but are not referenced in the database
    SELECT array_agg(f)
    INTO orphaned_files
    FROM unnest(all_files) AS f
    WHERE f <> ALL(used_files);

    IF array_length(orphaned_files, 1) > 0 THEN
        RAISE LOG 'Found % orphaned files to delete: %', array_length(orphaned_files, 1), orphaned_files;
        PERFORM storage.delete_objects(bucket_name, orphaned_files);
    ELSE
        RAISE LOG 'No orphaned files found in bucket %.', bucket_name;
    END IF;

END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
COMMENT ON FUNCTION public.cleanup_orphaned_images() IS 'Deletes files from the event-images bucket that are no longer referenced in the events table.';

-- Step 6: Schedule the cleanup job to run daily at 3 AM UTC.
SELECT cron.schedule(
    'daily-orphan-cleanup',
    '0 3 * * *',
    'SELECT cleanup_orphaned_images()'
);

-- Step 7: Re-create other helper functions for the chat application.
-- (These are included for completeness of the reset script)

CREATE OR REPLACE FUNCTION get_all_communities(p_user_id UUID)
RETURNS TABLE (
    id UUID, created_at TIMESTAMPTZ, name TEXT, description TEXT, visibility TEXT,
    join_code TEXT, creator_id UUID, creator_name TEXT, member_count BIGINT,
    is_member BOOLEAN, is_creator BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        c.id, c.created_at, c.name, c.description, c.visibility, c.join_code, c.creator_id,
        u.username AS creator_name,
        (SELECT count(*) FROM public.memberships WHERE community_id = c.id) AS member_count,
        EXISTS(SELECT 1 FROM public.memberships WHERE community_id = c.id AND user_id = p_user_id) AS is_member,
        (c.creator_id = p_user_id) AS is_creator
    FROM public.communities c
    LEFT JOIN public.users u ON c.creator_id = u.id
    WHERE
        c.visibility = 'public'
        OR c.creator_id = p_user_id
        OR EXISTS(SELECT 1 FROM public.memberships WHERE community_id = c.id AND user_id = p_user_id)
    ORDER BY c.created_at DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION get_joined_communities(p_user_id UUID)
RETURNS TABLE (id UUID, name TEXT, description TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT c.id, c.name, c.description
    FROM public.memberships m
    JOIN public.communities c ON m.community_id = c.id
    WHERE m.user_id = p_user_id AND c.creator_id <> p_user_id
    ORDER BY c.name;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION get_hosted_communities(p_user_id UUID)
RETURNS TABLE (id UUID, name TEXT, description TEXT, visibility TEXT, join_code TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT c.id, c.name, c.description, c.visibility, c.join_code
    FROM public.communities c
    WHERE c.creator_id = p_user_id
    ORDER BY c.name;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION get_poll_results(p_poll_id UUID)
RETURNS TABLE (id UUID, text TEXT, votes BIGINT, percent FLOAT) AS $$
DECLARE
    total_votes BIGINT;
BEGIN
    SELECT COALESCE(SUM(t.votes), 0) INTO total_votes
    FROM (
        SELECT count(pv.user_id) AS votes
        FROM public.poll_options po
        LEFT JOIN public.poll_votes pv ON po.id = pv.option_id
        WHERE po.poll_id = p_poll_id
        GROUP BY po.id
    ) t;

    RETURN QUERY
    SELECT
        po.id,
        po.option_text AS text,
        count(pv.user_id) AS votes,
        CASE
            WHEN total_votes > 0 THEN (count(pv.user_id)::FLOAT / total_votes * 100)
            ELSE 0
        END AS percent
    FROM public.poll_options po
    LEFT JOIN public.poll_votes pv ON po.id = pv.option_id
    WHERE po.poll_id = p_poll_id
    GROUP BY po.id, po.option_text
    ORDER BY po.id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION get_polls_for_community(p_community_id UUID, p_user_id UUID)
RETURNS TABLE (
    type TEXT, poll_id UUID, created_at TIMESTAMPTZ, user_id UUID,
    username TEXT, question TEXT, options JSON
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        'poll'::TEXT AS type,
        p.id AS poll_id,
        p.created_at,
        p.user_id,
        u.username,
        p.question,
        COALESCE(
            (
                SELECT json_agg(
                    json_build_object(
                        'id', po.id,
                        'text', po.option_text,
                        'votes', (SELECT COUNT(*) FROM public.poll_votes pv WHERE pv.option_id = po.id),
                        'percent', CASE
                            WHEN (SELECT COUNT(*) FROM public.poll_votes pv2 WHERE pv2.poll_id = p.id) > 0
                            THEN ((SELECT COUNT(*) FROM public.poll_votes pv WHERE pv.option_id = po.id)::FLOAT / (SELECT COUNT(*) FROM public.poll_votes pv3 WHERE pv3.poll_id = p.id) * 100)
                            ELSE 0
                        END,
                        'selected', EXISTS (SELECT 1 FROM public.poll_votes pv4 WHERE pv4.option_id = po.id AND pv4.user_id = p_user_id)
                    )
                    ORDER BY po.id
                )
                FROM public.poll_options po
                WHERE po.poll_id = p.id
            ),
            '[]'::JSON
        ) AS options
    FROM public.polls p
    JOIN public.users u ON p.user_id = u.id
    WHERE p.community_id = p_community_id
    ORDER BY p.created_at DESC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Final confirmation
SELECT 'Database reset and schema creation complete.' AS status;

-- DANGER: THIS SCRIPT WILL DELETE ALL USERS AND ALL DATA    
-- Run this to completely reset your application.            

-- Step 1: Delete all users from the authentication system.
-- This will cascade and delete their corresponding profiles in `public.users`.
DELETE FROM auth.users;

-- Step 2: Truncate all remaining public tables to clear all content.
-- This is faster than DELETE and resets any auto-incrementing counters.
-- The order respects foreign key relationships.
TRUNCATE 
    public.poll_votes,
    public.poll_options,
    public.polls,
    public.messages,
    public.memberships,
    public.events,
    public.communities
RESTART IDENTITY;

-- Step 3: Re-seed the default public communities for a clean start.
-- This ensures the default communities exist immediately after the reset.
DO $$
DECLARE
    default_communities JSONB := '[
        {"name": "General", "description": "A place for general discussions."},
        {"name": "Photography", "description": "Share your photos and discuss techniques."},
        {"name": "Coding", "description": "Talk about programming, frameworks, and more."},
        {"name": "Design", "description": "All things design: UI/UX, graphics, and art."},
        {"name": "Gaming", "description": "Discuss video games, find teammates, and share clips."}
    ]';
    comm_record JSONB;
BEGIN
    RAISE LOG 'Seeding default communities...';
    FOR comm_record IN SELECT * FROM jsonb_array_elements(default_communities)
    LOOP
        -- Check if community already exists (it shouldn't after TRUNCATE, but this is safe)
        IF NOT EXISTS (SELECT 1 FROM public.communities WHERE name = comm_record->>'name') THEN
            -- Community does not exist, create it as public
            INSERT INTO public.communities (name, description, visibility)
            VALUES (comm_record->>'name', comm_record->>'description', 'public');
            RAISE LOG 'Created default community: %', comm_record->>'name';
        END IF;
    END LOOP;
END $$;


-- Final confirmation message
SELECT 'Success: All users and application data have been deleted. The database is reset.' AS status;
