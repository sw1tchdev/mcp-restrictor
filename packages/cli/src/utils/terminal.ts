export function escapeControls(value: string): string {
  return value.replace(
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    (character) => {
      const escaped = JSON.stringify(character).slice(1, -1);
      return escaped === character
        ? `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`
        : escaped;
    },
  );
}
