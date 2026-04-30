function escapeHTML(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sanitizeURL(value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }

  if (/^(https?:\/\/|\/)/i.test(trimmed)) {
    return escapeHTML(trimmed);
  }

  return null;
}

function renderInlineMarkdown(source: string) {
  let content = source;
  const tokens: string[] = [];
  const pushToken = (html: string) => {
    const token = `@@MDT_${tokens.length}@@`;
    tokens.push(html);
    return token;
  };

  content = content.replace(/`([^`]+)`/g, (_match, code: string) =>
    pushToken(`<code class="markdown-inline-code">${escapeHTML(code)}</code>`),
  );
  content = content.replace(
    /!\[([^\]]*)\]\(([^)\s]+)(?:\s+"([^"]+)")?\)/g,
    (match: string, alt: string, url: string, title?: string) => {
      const safeURL = sanitizeURL(url);
      if (!safeURL) {
        return match;
      }

      const titleAttribute = title ? ` title="${escapeHTML(title)}"` : "";
      return pushToken(
        `<img class="markdown-image" src="${safeURL}" alt="${escapeHTML(alt)}" data-preview-src="${safeURL}" data-preview-alt="${escapeHTML(alt)}"${titleAttribute} loading="lazy" />`,
      );
    },
  );
  content = content.replace(
    /\[([^\]]+)\]\(([^)\s]+)(?:\s+"([^"]+)")?\)/g,
    (match: string, label: string, url: string, title?: string) => {
      const safeURL = sanitizeURL(url);
      if (!safeURL) {
        return match;
      }

      const titleAttribute = title ? ` title="${escapeHTML(title)}"` : "";
      return pushToken(
        `<a class="markdown-link" href="${safeURL}" target="_blank" rel="noreferrer"${titleAttribute}>${escapeHTML(label)}</a>`,
      );
    },
  );
  content = content.replace(/\*\*([^*]+)\*\*/g, (_match, value: string) => pushToken(`<strong>${escapeHTML(value)}</strong>`));
  content = content.replace(/__([^_]+)__/g, (_match, value: string) => pushToken(`<strong>${escapeHTML(value)}</strong>`));
  content = content.replace(/\*([^*]+)\*/g, (_match, value: string) => pushToken(`<em>${escapeHTML(value)}</em>`));
  content = content.replace(/(^|[^_])_([^_]+)_(?=[^_]|$)/g, (_match, prefix: string, value: string) =>
    `${prefix}${pushToken(`<em>${escapeHTML(value)}</em>`)}`,
  );

  const escaped = escapeHTML(content);
  return escaped.replace(/@@MDT_(\d+)@@/g, (_match, index: string) => tokens[Number(index)] ?? "");
}

function isFence(line: string) {
  return /^```/.test(line);
}

function isHeading(line: string) {
  return /^(#{1,6})\s+/.test(line);
}

function isBlockquote(line: string) {
  return /^>\s?/.test(line);
}

function isUnorderedListItem(line: string) {
  return /^[-*+]\s+/.test(line);
}

function isOrderedListItem(line: string) {
  return /^\d+\.\s+/.test(line);
}

function renderMarkdownToHTML(source: string) {
  const lines = source.replace(/\r\n?/g, "\n").split("\n");
  const parts: string[] = [];
  let index = 0;

  while (index < lines.length) {
    const currentLine = lines[index];

    if (!currentLine.trim()) {
      index += 1;
      continue;
    }

    if (isFence(currentLine)) {
      const codeLines: string[] = [];
      index += 1;

      while (index < lines.length && !isFence(lines[index])) {
        codeLines.push(lines[index]);
        index += 1;
      }

      if (index < lines.length && isFence(lines[index])) {
        index += 1;
      }

      parts.push(`<pre class="markdown-code"><code>${escapeHTML(codeLines.join("\n"))}</code></pre>`);
      continue;
    }

    const headingMatch = currentLine.match(/^(#{1,6})\s+(.*)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      parts.push(
        `<h${level} class="markdown-heading markdown-heading-${level}">${renderInlineMarkdown(headingMatch[2].trim())}</h${level}>`,
      );
      index += 1;
      continue;
    }

    if (isBlockquote(currentLine)) {
      const quoteLines: string[] = [];
      while (index < lines.length && isBlockquote(lines[index])) {
        quoteLines.push(lines[index].replace(/^>\s?/, ""));
        index += 1;
      }

      parts.push(
        `<blockquote class="markdown-blockquote">${quoteLines.map((line) => renderInlineMarkdown(line)).join("<br />")}</blockquote>`,
      );
      continue;
    }

    if (isUnorderedListItem(currentLine) || isOrderedListItem(currentLine)) {
      const ordered = isOrderedListItem(currentLine);
      const listItems: string[] = [];

      while (index < lines.length && lines[index].trim()) {
        if (ordered && !isOrderedListItem(lines[index])) {
          break;
        }
        if (!ordered && !isUnorderedListItem(lines[index])) {
          break;
        }

        listItems.push(lines[index].replace(ordered ? /^\d+\.\s+/ : /^[-*+]\s+/, ""));
        index += 1;
      }

      const tag = ordered ? "ol" : "ul";
      parts.push(
        `<${tag} class="markdown-list">${listItems.map((item) => `<li>${renderInlineMarkdown(item)}</li>`).join("")}</${tag}>`,
      );
      continue;
    }

    const paragraphLines: string[] = [];
    while (index < lines.length && lines[index].trim()) {
      if (
        paragraphLines.length > 0 &&
        (isFence(lines[index]) || isHeading(lines[index]) || isBlockquote(lines[index]) || isUnorderedListItem(lines[index]) || isOrderedListItem(lines[index]))
      ) {
        break;
      }

      paragraphLines.push(lines[index]);
      index += 1;
    }

    parts.push(`<p class="markdown-paragraph">${paragraphLines.map((line) => renderInlineMarkdown(line)).join("<br />")}</p>`);
  }

  return parts.join("");
}

export function MarkdownRenderer({
  content,
  onImageClick,
}: {
  content: string;
  onImageClick?: (payload: { url: string; alt: string }) => void;
}) {
  const normalized = content.trim();
  if (!normalized) {
    return <div className="muted-text">暂无描述</div>;
  }

  return (
    <div
      className="markdown-content"
      dangerouslySetInnerHTML={{ __html: renderMarkdownToHTML(normalized) }}
      onClick={(event) => {
        if (!onImageClick) {
          return;
        }

        const target = event.target;
        if (!(target instanceof HTMLImageElement)) {
          return;
        }

        const url = target.dataset.previewSrc;
        if (!url) {
          return;
        }

        onImageClick({
          url,
          alt: target.dataset.previewAlt ?? target.alt ?? "图片预览",
        });
      }}
    />
  );
}
