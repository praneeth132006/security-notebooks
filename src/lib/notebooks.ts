import manifest from '../generated/notebooks.json';

export interface Chapter {
	slug: string;
	title: string;
	number: number;
	level: string;
	minutes: number;
}

export interface Notebook {
	slug: string;
	label: string;
	field: string;
	notebookNumber: number;
	chapters: Chapter[];
}

export const notebooks = manifest as Notebook[];

const base = import.meta.env.BASE_URL.replace(/\/$/, '');

/** Absolute site path for a notebook (`linux`) or chapter (`linux/01-intro`). */
export function href(id: string): string {
	return `${base}/${id}/`;
}

/** Resolve a Starlight route id to its notebook and, for chapter pages, the chapter. */
export function lookup(routeId: string) {
	const [bookSlug, chapterSlug] = routeId.replace(/\/$/, '').split('/');
	const notebook = notebooks.find((n) => n.slug === bookSlug);
	if (!notebook) return null;
	const index = chapterSlug ? notebook.chapters.findIndex((c) => c.slug === chapterSlug) : -1;
	return { notebook, chapter: index >= 0 ? notebook.chapters[index] : null, index };
}

export function formatMinutes(total: number): string {
	if (total < 60) return `${total} min`;
	const hours = Math.round(total / 6) / 10;
	return `${hours} h`;
}

/* The roadmap groups the curriculum's fields into five phases, in the order
   a learner would take them. Fields not listed fall into "Specialize". */
export const PHASES: { name: string; blurb: string; fields: string[] }[] = [
	{
		name: 'Foundations',
		blurb: 'Linux, networking, Windows, the web, and crypto. Everything else builds on these.',
		fields: ['Foundations'],
	},
	{
		name: 'Offense',
		blurb: 'Think like an attacker: methodology, exploitation, web bugs, and red team operations.',
		fields: ['Penetration Testing', 'Bug Bounty & AppSec', 'Red Team'],
	},
	{
		name: 'Defense',
		blurb: 'Detect, investigate, and respond: SOC work, forensics, threat hunting, and purple teaming.',
		fields: ['SOC & Blue Team', 'DFIR', 'Threat Intel & Hunting', 'Purple Team'],
	},
	{
		name: 'Specialize',
		blurb: 'Go deep on one area: reverse engineering, cloud, mobile, AI, product security, and more.',
		fields: [],
	},
	{
		name: 'Career',
		blurb: 'Practice with CTFs, pick a path, and land the role.',
		fields: ['Career'],
	},
];

export function phases() {
	const named = new Set(PHASES.flatMap((p) => p.fields));
	return PHASES.map((phase) => {
		const fields = phase.fields.length
			? phase.fields
			: [...new Set(notebooks.map((n) => n.field))].filter((f) => !named.has(f));
		const books = notebooks.filter((n) => fields.includes(n.field));
		return { ...phase, books };
	}).filter((p) => p.books.length > 0);
}
