// @ts-check
import fs from 'node:fs';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';
import { unified } from '@astrojs/markdown-remark';
import remarkHtmlAsText from './src/plugins/remark-html-as-text.mjs';

/* Written by the sync script in the private source repo.
   Books arrive in curriculum order, each tagged with its field. */
const notebooks = fs.existsSync('./src/generated/notebooks.json')
	? JSON.parse(fs.readFileSync('./src/generated/notebooks.json', 'utf8'))
	: [];

/** @type {{ label: string, collapsed: boolean, items: any[] }[]} */
const sidebar = [];
for (const book of notebooks) {
	let group = sidebar.find((g) => g.label === book.field);
	if (!group) sidebar.push((group = { label: book.field, collapsed: true, items: [] }));
	group.items.push({ label: book.label, collapsed: true, items: [{ autogenerate: { directory: book.slug } }] });
}

export default defineConfig({
	site: 'https://praneeth132006.github.io',
	base: '/security-notebooks',
	markdown: {
		processor: unified({ remarkPlugins: [remarkHtmlAsText] }),
	},
	integrations: [
		// Must come before starlight so ```mermaid blocks skip Expressive Code.
		mermaid({ autoTheme: true }),
		starlight({
			title: 'Security Notebooks',
			description: 'Free cybersecurity notebooks, from Linux fundamentals to red team operations.',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/praneeth132006/security-notebooks' },
			],
			lastUpdated: false,
			customCss: ['@fontsource-variable/inter', './src/styles/custom.css'],
			components: {
				PageTitle: './src/components/PageTitle.astro',
				Footer: './src/components/Footer.astro',
			},
			expressiveCode: {
				themes: ['github-dark-default', 'github-light-default'],
				defaultProps: { wrap: true },
				styleOverrides: { borderRadius: '0.5rem', codeFontSize: '0.85rem' },
			},
			sidebar,
		}),
	],
});
