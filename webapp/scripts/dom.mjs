// Gives the browser modules the DOM APIs they expect when run under Node.
import { JSDOM } from 'jsdom';

const { window } = new JSDOM('');
globalThis.DOMParser = window.DOMParser;
globalThis.XMLSerializer = window.XMLSerializer;
globalThis.Node = window.Node;
