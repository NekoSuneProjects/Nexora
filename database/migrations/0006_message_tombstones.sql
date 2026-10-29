
-- Deletion metadata only; retain until an approved policy applies.
CREATE TABLE IF NOT EXISTS message_tombstones (
 id uuid PRIMARY KEY,
 channel_id uuid NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
 deleted_by uuid REFERENCES users(id) ON DELETE SET NULL,
 deleted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS message_tombstones_channel_idx ON message_tombstones(channel_id,deleted_at,id);
