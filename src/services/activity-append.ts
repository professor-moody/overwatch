import type {
  ActivityLogEntry,
} from './engine-context.js';
import type { ChainCheckpoint } from './activity-chain.js';

export const ACTIVITY_APPEND_PAYLOAD_VERSION = 1 as const;

export interface ActivityActionFrontierValueV1 {
  frontier_item_id: string;
  agent_id?: string;
  frontier_type?: ActivityLogEntry['frontier_type'];
}

export interface ActivityAppendItemV1 {
  entry: ActivityLogEntry;
  checkpoint?: ChainCheckpoint;
}

export interface ActivityAppendContinuityV1 {
  activity_length: number;
  activity_tail_event_id: string | null;
  last_chain_hash: string;
  chain_events_since_checkpoint: number;
  checkpoint_count: number;
  checkpoint_tail_event_id: string | null;
  deterministic_seq: number;
}

export interface ActivityAppendPayloadV1 {
  payload_version: typeof ACTIVITY_APPEND_PAYLOAD_VERSION;
  items: ActivityAppendItemV1[];
  result_event_id: string;
  expected: ActivityAppendContinuityV1;
  final: Pick<
    ActivityAppendContinuityV1,
    'last_chain_hash' | 'chain_events_since_checkpoint' | 'deterministic_seq'
  >;
  action_frontier_update?: {
    action_id: string;
    before: ActivityActionFrontierValueV1 | null;
    after: ActivityActionFrontierValueV1;
  };
}
