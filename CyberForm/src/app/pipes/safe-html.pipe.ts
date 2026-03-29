import { Pipe, PipeTransform } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import DOMPurify from 'dompurify';

/**
 * HTML issu du backend (formation, feedback) : DOMPurify retire scripts / événements
 * dangereux avant affichage ; bypass Angular uniquement sur le résultat nettoyé.
 */
@Pipe({ name: 'safeHtml' })
export class SafeHtmlPipe implements PipeTransform {
  constructor(private sanitizer: DomSanitizer) {}

  transform(value: string | null | undefined): SafeHtml {
    const cleaned = DOMPurify.sanitize(value ?? '', {
      USE_PROFILES: { html: true },
    });
    return this.sanitizer.bypassSecurityTrustHtml(cleaned);
  }
}
