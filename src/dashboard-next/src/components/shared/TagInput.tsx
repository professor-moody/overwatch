import { useState, useCallback } from 'react';
import { cn } from '../../lib/utils';

export function TagInput({
  tags,
  onChange,
  placeholder = 'Add item\u2026',
  className,
}: {
  tags: string[];
  onChange: (tags: string[]) => void;
  placeholder?: string;
  className?: string;
}) {
  const [input, setInput] = useState('');

  const addTag = useCallback(() => {
    const val = input.trim().replace(/,$/, '');
    if (!val || tags.includes(val)) return;
    onChange([...tags, val]);
    setInput('');
  }, [input, tags, onChange]);

  const removeTag = useCallback((index: number) => {
    onChange(tags.filter((_, i) => i !== index));
  }, [tags, onChange]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addTag();
    }
    if (e.key === 'Backspace' && !input && tags.length > 0) {
      onChange(tags.slice(0, -1));
    }
  }, [addTag, input, tags, onChange]);

  return (
    <div className={cn('space-y-2', className)}>
      <div className="flex flex-wrap gap-1.5">
        {tags.map((tag, i) => (
          <span
            key={`${tag}-${i}`}
            className="inline-flex items-center gap-1 bg-elevated text-xs text-foreground px-2 py-0.5 rounded border border-border"
          >
            <span className="font-mono">{tag}</span>
            <button
              type="button"
              onClick={() => removeTag(i)}
              className="text-muted-foreground hover:text-destructive transition-colors ml-0.5"
            >
              &times;
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={placeholder}
          className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs text-foreground placeholder:text-muted focus:outline-none focus:border-accent"
        />
        <button
          type="button"
          onClick={addTag}
          className="text-xs px-2 py-1 rounded bg-elevated border border-border text-muted-foreground hover:text-foreground hover:border-border-strong transition-colors"
        >
          Add
        </button>
      </div>
    </div>
  );
}
