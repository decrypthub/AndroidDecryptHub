// Named phone recipes ("skills"): a flow the AI worked out once can be replayed in one call.
//
// Host-side only and deliberately dumb: a skill is a validated, bounded list of the same
// primitives phone_task exposes. It carries no shell, no arbitrary code and no way to nest
// skills, so replaying one cannot widen what the automation surface is allowed to do.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export interface PhoneSkill {
  name: string;
  description?: string;
  steps: any[];
  createdAt?: number;
  updatedAt?: number;
  runs?: number;
  lastRunAt?: number;
}

export const SKILL_STEP_TYPES = ['observe', 'find', 'wait', 'act', 'app', 'device'];
const SKILL_NAME = /^[a-z0-9][a-z0-9_.-]{0,39}$/i;
const MAX_STEPS = 30;

export function validateSkillName(name: unknown): string {
  const value = String(name ?? '').trim();
  if (!SKILL_NAME.test(value)) throw new Error('invalid_skill_name: use 1-40 chars of [A-Za-z0-9_.-], starting alphanumeric');
  return value;
}

export function validateSkillSteps(steps: unknown): any[] {
  if (!Array.isArray(steps) || steps.length === 0) throw new Error('invalid_skill_steps: steps must be a non-empty array');
  if (steps.length > MAX_STEPS) throw new Error(`invalid_skill_steps: at most ${MAX_STEPS} steps`);
  steps.forEach((step: any, index: number) => {
    const type = String(step?.type ?? '');
    if (!SKILL_STEP_TYPES.includes(type)) throw new Error(`invalid_skill_steps: step ${index} has unsupported type '${type}' (allowed: ${SKILL_STEP_TYPES.join(', ')})`);
    if (step?.args != null && (typeof step.args !== 'object' || Array.isArray(step.args))) throw new Error(`invalid_skill_steps: step ${index} args must be an object`);
  });
  return steps as any[];
}

export class PhoneSkillStore {
  private skills = new Map<string, PhoneSkill>();
  private file: string;

  // NB: no TS parameter properties — node runs these files with type-stripping only.
  constructor(file: string) {
    this.file = file;
    this.skills = this.load();
  }

  private load(): Map<string, PhoneSkill> {
    const map = new Map<string, PhoneSkill>();
    try {
      if (!existsSync(this.file)) return map;
      const parsed = JSON.parse(readFileSync(this.file, 'utf8'));
      for (const skill of Array.isArray(parsed?.skills) ? parsed.skills : []) {
        try { validateSkillName(skill?.name); validateSkillSteps(skill?.steps); } catch { continue; }
        map.set(skill.name, skill);
      }
    } catch { /* corrupt store: start empty, keep serving */ }
    return map;
  }

  private persist() {
    mkdirSync(dirname(this.file), { recursive: true });
    const temp = `${this.file}.tmp`;
    writeFileSync(temp, JSON.stringify({ version: 1, skills: [...this.skills.values()] }, null, 2));
    renameSync(temp, this.file);
  }

  list(): any[] {
    return [...this.skills.values()]
      .sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
      .map((skill) => ({ name: skill.name, description: skill.description ?? '', steps: skill.steps.length, runs: skill.runs ?? 0, updatedAt: skill.updatedAt ?? 0, lastRunAt: skill.lastRunAt ?? 0 }));
  }

  get(name: string): PhoneSkill | undefined {
    return this.skills.get(name);
  }

  save(name: string, description: string | undefined, steps: unknown, overwrite: boolean): PhoneSkill {
    const key = validateSkillName(name);
    const valid = validateSkillSteps(steps);
    const existing = this.skills.get(key);
    if (existing && !overwrite) throw new Error(`skill_exists: '${key}' already exists (pass overwrite:true to replace)`);
    const now = Date.now();
    const skill: PhoneSkill = {
      name: key,
      description: description ? String(description).slice(0, 200) : undefined,
      steps: valid,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      runs: existing?.runs ?? 0,
      lastRunAt: existing?.lastRunAt ?? 0,
    };
    this.skills.set(key, skill);
    this.persist();
    return skill;
  }

  remove(name: string): boolean {
    const removed = this.skills.delete(String(name));
    if (removed) this.persist();
    return removed;
  }

  noteRun(name: string) {
    const skill = this.skills.get(name);
    if (!skill) return;
    skill.runs = (skill.runs ?? 0) + 1;
    skill.lastRunAt = Date.now();
    this.persist();
  }
}
