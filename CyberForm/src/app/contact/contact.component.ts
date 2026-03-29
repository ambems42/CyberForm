import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { finalize } from 'rxjs/operators';
import { TranslateService } from '@ngx-translate/core';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-contact',
  templateUrl: './contact.component.html',
  styleUrls: ['./contact.component.css']
})
export class ContactComponent {
  contact = {
    nom: '',
    email: '',
    message: ''
  };

  confirmation = false;
  errorMessage = '';
  sending = false;

  constructor(
    private http: HttpClient,
    private translate: TranslateService
  ) {}

  envoyerMessage(): void {
    this.errorMessage = '';
    this.confirmation = false;
    this.sending = true;
    this.http
      .post<{ message?: string }>(apiUrl('/api/contact'), {
        nom: this.contact.nom.trim(),
        email: this.contact.email.trim(),
        message: this.contact.message.trim(),
      })
      .pipe(finalize(() => (this.sending = false)))
      .subscribe({
        next: () => {
          this.confirmation = true;
          this.contact = { nom: '', email: '', message: '' };
        },
        error: (err: { error?: { error?: string } }) => {
          this.confirmation = false;
          this.errorMessage =
            err?.error?.error ||
            this.translate.instant('CONTACT.ERR_SEND');
        },
      });
  }
}
