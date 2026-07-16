import { z } from 'zod';

export const OperatorOpSchema = z.discriminatedUnion('op', [
  z.object({
    op: z.literal('directive'),
    task_id: z.string(),
    agent_label: z.string(),
    kind: z.enum([
      'pause',
      'resume',
      'stop',
      'narrow_scope',
      'skip_types',
      'prioritize',
      'instruct',
    ]),
    node_ids: z.array(z.string()).optional(),
    frontier_types: z.array(z.string()).optional(),
    note: z.string().optional(),
  }).strict(),
  z.object({
    op: z.literal('scope'),
    add_cidrs: z.array(z.string()).optional(),
    add_domains: z.array(z.string()).optional(),
    add_exclusions: z.array(z.string()).optional(),
  }).strict(),
  z.object({
    op: z.literal('approve'),
    action_id: z.string(),
    notes: z.string().optional(),
  }).strict(),
  z.object({
    op: z.literal('deny'),
    action_id: z.string(),
    reason: z.string().optional(),
  }).strict(),
  z.object({
    op: z.literal('dispatch'),
    target_node_ids: z.array(z.string()).min(1),
    archetype: z.string().optional(),
    skill: z.string().optional(),
    objective: z.string().optional(),
  }).strict(),
]);

export const OperatorOpsSchema = z.array(OperatorOpSchema).min(1);
