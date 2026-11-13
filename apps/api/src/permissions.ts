// Nexora-native permission bits. These are deliberately NOT Discord's bit layout; a
// future Discord compatibility adapter must translate explicitly.
export const Permissions = {
  ADMINISTRATOR: 1n << 0n,
  MANAGE_GUILD: 1n << 1n,
  MANAGE_ROLES: 1n << 2n,
  MANAGE_CHANNELS: 1n << 3n,
  KICK_MEMBERS: 1n << 4n,
  BAN_MEMBERS: 1n << 5n,
  CREATE_INVITE: 1n << 6n,
  MANAGE_NICKNAMES: 1n << 7n,
  CHANGE_NICKNAME: 1n << 8n,
  MANAGE_MESSAGES: 1n << 9n,
  SEND_MESSAGES: 1n << 10n,
  ADD_REACTIONS: 1n << 11n,
  VIEW_AUDIT_LOG: 1n << 12n,
  MANAGE_BOTS: 1n << 13n,
  MENTION_EVERYONE: 1n << 14n,
} as const;
export type PermissionName = keyof typeof Permissions;
export const ALL_PERMISSIONS = Object.values(Permissions).reduce((a, b) => a | b, 0n);
// Kept in sync with the @everyone default inserted by migration 0008 (3392).
export const DEFAULT_PERMISSIONS =
  Permissions.CREATE_INVITE | Permissions.CHANGE_NICKNAME | Permissions.SEND_MESSAGES | Permissions.ADD_REACTIONS;

export function has(granted: bigint, needed: bigint) {
  if (granted & Permissions.ADMINISTRATOR) return true;
  return (granted & needed) === needed;
}
export function parsePermissionInput(value: unknown): bigint | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  try {
    const parsed = BigInt(value);
    if (parsed < 0n || parsed > ALL_PERMISSIONS || (parsed & ~ALL_PERMISSIONS) !== 0n) return null;
    return parsed;
  } catch {
    return null;
  }
}
export function describe(bits: bigint): PermissionName[] {
  return (Object.keys(Permissions) as PermissionName[]).filter((k) => (bits & Permissions[k]) !== 0n);
}
