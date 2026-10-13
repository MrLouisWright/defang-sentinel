import type { Report, PolicyOptions, Severity } from './core.js';
export * from './core.js';
export type Style = 'brackets' | 'full' | 'dot' | 'minimal';
export interface LiveSpan { type: 'url' | 'email' | 'ipv4' | 'ipv6' | 'domain'; value: string; start: number; end: number; host?: string; }
export interface MatchOptions { ignoreDomains?: string[]; includePrivate?: boolean; fileNameDomains?: boolean; }
export interface CheckOptions extends MatchOptions, PolicyOptions { referenceDomains?: boolean; skipCode?: boolean; style?: Style; extensions?: string[]; }
export declare const STYLES: Style[];
export declare const REFERENCE_DOMAINS: string[];
export declare const DEFAULT_EXTENSIONS: string[];
export declare const VERSION: string;
export declare const RULES: Record<string, { severity: Severity; title: string; group: string }>;
export declare function refang(text: string): string;
export declare function refangText(text: string): { text: string; changes: number };
export declare function defangText(text: string, opts?: MatchOptions & { style?: Style }): { text: string; changes: number };
export declare function defangValue(value: string, type?: 'auto' | 'url' | 'email' | 'domain' | 'ipv6', style?: Style): string;
export declare function findLive(line: string, opts?: MatchOptions): LiveSpan[];
export declare function checkText(text: string, file: string, opts?: CheckOptions): object[];
export declare function check(inputs: (string | { name: string; text: string })[], opts?: CheckOptions): Report;
