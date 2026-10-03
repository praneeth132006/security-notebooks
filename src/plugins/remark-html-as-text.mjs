import { visit } from 'unist-util-visit';

/**
 * Show raw HTML in Markdown as literal text instead of rendering it.
 *
 * These are security notes: prose like "inject <script>alert(1)</script>"
 * must read as an example, never execute. The portfolio drops raw HTML
 * entirely; printing it keeps the example visible on the page.
 */
export default function remarkHtmlAsText() {
	return (tree) => {
		visit(tree, 'html', (node) => {
			node.type = 'text';
		});
	};
}
