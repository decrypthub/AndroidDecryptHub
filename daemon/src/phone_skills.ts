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
  params?: string[];                       // names the recipe expects, referenced as {{input.<name>}}
  defaults?: Record<string, any>;          // optional values for those names
  createdAt?: number;
  updatedAt?: number;
  runs?: number;
  lastRunAt?: number;
}

export const SKILL_STEP_TYPES = ['observe', 'find', 'wait', 'wait_any', 'act', 'app', 'device'];
const SKILL_NAME = /^[a-z0-9][a-z0-9_.-]{0,39}$/i;
const MAX_STEPS = 30;

const PARAM = /^[A-Za-z_][A-Za-z0-9_-]{0,30}$/;

export function validateSkillParams(params: unknown): string[] {
  if (params == null) return [];
  if (!Array.isArray(params)) throw new Error('invalid_skill_params: params must be an array of names');
  if (params.length > 10) throw new Error('invalid_skill_params: at most 10 params');
  const names = params.map((value) => String(value ?? '').trim());
  for (const name of names) {
    if (!PARAM.test(name)) throw new Error(`invalid_skill_params: '${name}' is not a usable name (letters/digits/_/- , starting with a letter or _)`);
    if (name === 'input') throw new Error("invalid_skill_params: 'input' is reserved (steps read it as {{input.<name>}})");
  }
  if (new Set(names).size !== names.length) throw new Error('invalid_skill_params: duplicate names');
  return names;
}

// Merge caller inputs with the recipe defaults and fail loudly when something required is absent,
// so a run never silently proceeds with an empty value baked into an action.
export function resolveSkillInputs(skill: { params?: string[]; defaults?: Record<string, any> }, provided: unknown): Record<string, any> {
  const given = provided && typeof provided === 'object' && !Array.isArray(provided) ? { ...(provided as Record<string, any>) } : {};
  const merged: Record<string, any> = { ...(skill.defaults ?? {}), ...given };
  const missing = (skill.params ?? []).filter((name) => merged[name] === undefined || merged[name] === null);
  if (missing.length) throw new Error(`skill_missing_input: ${missing.join(', ')} (pass inputs: { ${missing.map((n) => `${n}: ...`).join(', ')} })`);
  return merged;
}

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

/**
 * Predicts which app a recipe's steps assume, so the save call can warn when nothing establishes
 * that state. A step that acts on a bare screen silently depends on whatever was there when the
 * run started - exactly how a recorded flow works once and then fails on replay. Warnings are
 * advisory with the step index; recipes stay saveable.
 */
export function skillPreflightIssues(steps: any[]): string[] {
  const issues: string[] = [];
  let established = false;
  (steps ?? []).forEach((step: any, index: number) => {
    const type = String(step?.type ?? '');
    if (type === 'app') {
      const action = String(step?.args?.action ?? 'open');
      if (action === 'open' || action === 'restart') established = true;
      return;
    }
    if (type === 'device') return;
    if (type === 'wait_any') {
      const hasState = Array.isArray(step?.args?.conditions)
        && step.args.conditions.some((condition: any) => condition && (condition.activePackage != null || condition.text != null || condition.textContains != null));
      if (hasState) established = true;
      return;
    }
    if (type === 'wait') {
      if (step?.args?.activePackage != null || step?.args?.activityContains != null) established = true;
      return;
    }
    if ((type === 'act' || type === 'observe' || type === 'find') && !established) {
      issues.push('step_' + index + '_no_app_context: this ' + type + ' step runs on whatever screen happens to be current; open an app first, wait for activePackage, or guard the step with onlyIf.');
    }
  });
  return issues;
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
      .map((skill) => ({
        name: skill.name,
        description: skill.description ?? '',
        steps: skill.steps.length,
        params: skill.params ?? [],
        defaults: skill.defaults ?? {},
        runs: skill.runs ?? 0,
        updatedAt: skill.updatedAt ?? 0,
        lastRunAt: skill.lastRunAt ?? 0,
      }));
  }

  get(name: string): PhoneSkill | undefined {
    return this.skills.get(name);
  }

  save(name: string, description: string | undefined, steps: unknown, overwrite: boolean, params?: unknown, defaults?: unknown): PhoneSkill {
    const key = validateSkillName(name);
    const valid = validateSkillSteps(steps);
    const validParams = validateSkillParams(params);
    const validDefaults = defaults && typeof defaults === 'object' && !Array.isArray(defaults) ? { ...(defaults as Record<string, any>) } : {};
    for (const name of Object.keys(validDefaults)) {
      if (!validParams.includes(name)) throw new Error(`invalid_skill_params: default for unknown param '${name}'`);
    }
    const existing = this.skills.get(key);
    if (existing && !overwrite) throw new Error(`skill_exists: '${key}' already exists (pass overwrite:true to replace)`);
    const now = Date.now();
    const skill: PhoneSkill = {
      name: key,
      description: description ? String(description).slice(0, 200) : undefined,
      steps: valid,
      params: validParams,
      defaults: validDefaults,
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
