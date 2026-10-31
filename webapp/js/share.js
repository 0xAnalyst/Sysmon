// Share links: the config XML, deflate-compressed and base64url-encoded into the URL hash.
// Nothing is uploaded; the link itself carries the config.

const PREFIX = '#x=';

async function pipe(bytes, stream) {
  const out = new Blob([bytes]).stream().pipeThrough(stream);
  return new Uint8Array(await new Response(out).arrayBuffer());
}

function toB64Url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64Url(str) {
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(s, c => c.charCodeAt(0));
}

export async function encodeShare(xml) {
  const packed = await pipe(new TextEncoder().encode(xml), new CompressionStream('deflate-raw'));
  return location.origin + location.pathname + PREFIX + toB64Url(packed);
}

export function hasShare() {
  return location.hash.startsWith(PREFIX);
}

export async function decodeShare() {
  const bytes = await pipe(fromB64Url(location.hash.slice(PREFIX.length)), new DecompressionStream('deflate-raw'));
  return new TextDecoder().decode(bytes);
}

export function clearShare() {
  history.replaceState(null, '', location.pathname + location.search);
}
