import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { en } from './locales/en';
import { ptBR } from './locales/pt-BR';

export const LANGUAGE_STORAGE_KEY = 'openshield.lang';

export type SupportedLanguage = 'pt-BR' | 'en';

export const SUPPORTED_LANGUAGES: {
  code: SupportedLanguage;
  shortLabel: string;
  label: string;
}[] = [
  { code: 'pt-BR', shortLabel: 'PT-BR', label: 'Português (BR)' },
  { code: 'en', shortLabel: 'EN', label: 'English' },
];

function detectInitialLanguage(): SupportedLanguage {
  if (typeof window !== 'undefined') {
    const saved = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (saved === 'en' || saved === 'pt-BR') {
      return saved;
    }
    const navLang = window.navigator.language?.toLowerCase() ?? '';
    if (navLang.startsWith('en')) {
      return 'en';
    }
  }
  return 'pt-BR';
}

export function getIntlLocale(lang: string): string {
  return lang === 'en' ? 'en-US' : 'pt-BR';
}

const initialLanguage = detectInitialLanguage();

void i18n.use(initReactI18next).init({
  resources: {
    'pt-BR': { translation: ptBR },
    en: { translation: en },
  },
  lng: initialLanguage,
  fallbackLng: 'pt-BR',
  interpolation: {
    escapeValue: false,
  },
});

if (typeof document !== 'undefined') {
  document.documentElement.lang = initialLanguage;
  document.title = i18n.t('meta.title');
}

i18n.on('languageChanged', (lng) => {
  if (typeof window !== 'undefined') {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, lng);
  }
  if (typeof document !== 'undefined') {
    document.documentElement.lang = lng;
    document.title = i18n.t('meta.title');
  }
});

export default i18n;
