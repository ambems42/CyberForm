import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { TranslateService } from '@ngx-translate/core';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-forgot-password',
  templateUrl: './forgot-password.component.html',
  styleUrls: ['./forgot-password.component.css']
})
export class ForgotPasswordComponent {
  email: string = '';
  message: string = '';
  error: string = '';

  constructor(
    private http: HttpClient,
    private translate: TranslateService
  ) {}

  requestReset() {
    this.message = '';
    this.error = '';

    if (!this.email) {
      this.error = this.translate.instant('FORGOT_PASSWORD.ERR_EMAIL_REQUIRED');
      return;
    }

    this.http.post<any>(apiUrl('/request-reset'), { email: this.email })
      .subscribe({
        next: (res) => {
          this.message = res.message;
        },
        error: (err) => {
          this.error = err.error?.error || this.translate.instant('FORGOT_PASSWORD.ERR_GENERIC');
        }
      });
  }
}
