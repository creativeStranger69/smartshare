/**
 * lib/langdetect.js - guess the language of a message from the ALPHABET (script) it is written in.
 *
 *   اردو / ہے / ٹ        -> Urdu          हिन्दी            -> Hindi
 *   বাংলা                -> Bengali       中文 / 日本語     -> Chinese / Japanese  ...
 *
 * Fast, free, offline - and good enough to (a) skip messages that are already in the reader's
 * language and (b) tell the translation service what the source language is.
 *
 * KNOWN LIMITS (be upfront in the viva):
 *  - Latin script is assumed to be English. "Roman Urdu" / "Hinglish" ("kya haal hai") is written in
 *    the Latin alphabet, so it cannot be told apart from English by script.
 *  - Devanagari is assumed Hindi (Marathi/Nepali share it); Arabic script: Urdu vs Persian vs Arabic is
 *    decided by letters unique to each language.
 */
const SCRIPTS = [
  ['arabic', /[؀-ۿݐ-ݿࢠ-ࣿﭐ-﷿ﹰ-﻿]/g],
  ['devanagari', /[ऀ-ॿ]/g],
  ['bengali', /[ঀ-৿]/g],
  ['gurmukhi', /[਀-੿]/g],
  ['gujarati', /[઀-૿]/g],
  ['tamil', /[஀-௿]/g],
  ['telugu', /[ఀ-౿]/g],
  ['kannada', /[ಀ-೿]/g],
  ['malayalam', /[ഀ-ൿ]/g],
  ['cyrillic', /[Ѐ-ӿ]/g],
  ['kana', /[぀-ヿ]/g],
  ['han', /[一-鿿]/g],
  ['hangul', /[가-힯]/g],
  ['latin', /[A-Za-zÀ-ɏ]/g],
];
const SCRIPT_LANG = { devanagari: 'hi', bengali: 'bn', gurmukhi: 'pa', gujarati: 'gu', tamil: 'ta', telugu: 'te', kannada: 'kn',
  malayalam: 'ml', cyrillic: 'ru', kana: 'ja', han: 'zh', hangul: 'ko', latin: 'en' };

const URDU_ONLY = /[ٹڈڑںھہے]/;        // ٹ ڈ ڑ ں ھ ہ ے
const PERSIAN_ONLY = /[پچژگ]/;                         // پ چ ژ گ (also used in Urdu, so checked second)

function arabicScriptLanguage(text) {
  if (URDU_ONLY.test(text)) return 'ur';
  if (PERSIAN_ONLY.test(text)) return 'fa';
  return 'ar';
}

/** @returns {{lang: string, confidence: number} | null}  null = no letters at all (numbers, emoji, symbols) */
function detectLanguage(text) {
  if (typeof text !== 'string') return null;
  const counts = SCRIPTS.map(([name, re]) => [name, (text.match(re) || []).length]);
  const total = counts.reduce((s, [, n]) => s + n, 0);
  if (!total) return null;
  const [script, n] = counts.reduce((best, c) => (c[1] > best[1] ? c : best));
  let lang;
  if (script === 'arabic') lang = arabicScriptLanguage(text);
  else if (script === 'han' && (counts.find(([s]) => s === 'kana')[1] > 0)) lang = 'ja';   // Japanese mixes kana + kanji
  else lang = SCRIPT_LANG[script];
  return { lang, confidence: script === 'latin' ? Math.min(0.5, n / total) : n / total };
}

const hasLetters = (text) => detectLanguage(text) !== null;

module.exports = { detectLanguage, hasLetters };
