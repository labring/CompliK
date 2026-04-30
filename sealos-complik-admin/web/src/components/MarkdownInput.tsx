import { MarkdownRenderer } from "./MarkdownRenderer";

type MarkdownInputProps = {
  placeholder?: string;
  value: string;
  onChange: (value: string) => void;
};

export function MarkdownInput({
  placeholder = "",
  value,
  onChange,
}: MarkdownInputProps) {
  return (
    <div className="markdown-input-shell">
      <div className="markdown-input-editor">
        <textarea
          className="text-area markdown-input-textarea"
          placeholder={placeholder}
          spellCheck={false}
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
      </div>
      <div className="markdown-input-preview">
        {value.trim() ? <MarkdownRenderer content={value} /> : <div className="markdown-input-empty" />}
      </div>
    </div>
  );
}
