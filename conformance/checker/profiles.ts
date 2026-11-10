// The subject profiles this verifier supports (AR-35 step 6: any other gives `profile_unavailable`).
import type { SubjectProfile } from './profile.ts';
import { X402EV1_PROFILE } from './subject.ts';
import { WAR12_PROFILE } from './subject-war.ts';

export const PROFILES: readonly SubjectProfile[] = [X402EV1_PROFILE, WAR12_PROFILE];

export function profileFor(id: string | null | undefined): SubjectProfile | null {
  if (id === null || id === undefined) return null;
  return PROFILES.find((p) => p.id === id) ?? null;
}
