"""Bounded HTML text extraction for liveness and page fingerprints."""
from html.parser import HTMLParser

MAX_HTML_CHARS = 512 * 1024
MAX_HTML_DEPTH = 256
MAX_HTML_EVENTS = 25000


class HTMLBudgetError(ValueError):
    pass


def bounded_html(text: str) -> str:
    if not isinstance(text, str) or len(text) > MAX_HTML_CHARS:
        raise HTMLBudgetError('HTML exceeds the 512 Ki-character parsing budget')
    return text


class VisibleText(HTMLParser):
    VOID = frozenset(('area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                      'link', 'meta', 'param', 'source', 'track', 'wbr'))

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.parts = []
        self.events = 0

    def _event(self):
        self.events += 1
        if self.events > MAX_HTML_EVENTS:
            raise HTMLBudgetError('HTML exceeds the parser event budget')

    def handle_starttag(self, tag, attrs):
        self._event()
        attrs = {k: v if isinstance(v, str) else '' for k, v in attrs}
        style = ''.join(attrs.get('style', '').lower().split())
        hidden = (tag in ('script', 'style', 'template', 'noscript') or 'hidden' in attrs
                  or attrs.get('aria-hidden', '').lower() == 'true'
                  or 'display:none' in style or 'visibility:hidden' in style)
        if tag not in self.VOID:
            if len(self.stack) >= MAX_HTML_DEPTH:
                raise HTMLBudgetError('HTML nesting exceeds 256 levels')
            self.stack.append((tag, hidden or bool(self.stack and self.stack[-1][1])))

    def handle_endtag(self, tag):
        self._event()
        # Depth is capped; mismatched tags cannot cause unbounded stack scans.
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        self._event()
        if not self.stack or not self.stack[-1][1]:
            self.parts.append(data)


def visible_html_text(html: str) -> str:
    parser = VisibleText()
    try:
        parser.feed(bounded_html(html))
        parser.close()
    except (AssertionError, RecursionError) as exc:
        raise ValueError("Malformed HTML") from exc
    return ' '.join(parser.parts).lower()
