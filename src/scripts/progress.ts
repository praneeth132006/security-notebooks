/* Reading progress, kept only in this browser. Chapters are keyed by their
   route id ("linux/01-linux-fundamentals-and-filesystem"). Storage can be
   unavailable (private windows, blocked site data), so every access is
   guarded and the pages render fine without it. */
const KEY = 'sn:visited';

export function visited(): Set<string> {
	try {
		return new Set(JSON.parse(localStorage.getItem(KEY) ?? '[]'));
	} catch {
		return new Set();
	}
}

export function markVisited(id: string) {
	try {
		const all = visited();
		all.add(id);
		localStorage.setItem(KEY, JSON.stringify([...all]));
	} catch {
		/* Progress is a convenience; nothing to do. */
	}
}

/** Paint progress into any element carrying data-progress hooks. */
export function paint() {
	const seen = visited();
	const base = import.meta.env.BASE_URL.replace(/\/$/, '');

	// Individual chapters: timeline rows, step bar segments, sidebar links.
	document.querySelectorAll<HTMLElement>('[data-chapter]').forEach((el) => {
		el.toggleAttribute('data-visited', seen.has(el.dataset.chapter!));
	});
	document.querySelectorAll<HTMLAnchorElement>('.sidebar-content a[href]').forEach((a) => {
		const id = a.pathname.replace(base, '').replace(/^\/|\/$/g, '');
		a.toggleAttribute('data-visited', seen.has(id));
	});

	// Notebook totals: "3 of 10 read" plus a bar.
	document.querySelectorAll<HTMLElement>('[data-notebook]').forEach((el) => {
		const ids = (el.dataset.chapters ?? '').split(' ').filter(Boolean);
		const done = ids.filter((id) => seen.has(id)).length;
		el.style.setProperty('--done', String(ids.length ? done / ids.length : 0));
		const label = el.querySelector<HTMLElement>('[data-progress-label]');
		if (label) label.textContent = done ? `${done} of ${ids.length} read` : `${ids.length} chapters`;
	});
}
