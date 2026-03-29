import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { TranslateService } from '@ngx-translate/core';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-reset-password',
  templateUrl: './reset-password.component.html',
  styleUrls: ['./reset-password.component.css']
})
export class ResetPasswordComponent implements OnInit {
  token: string = '';
  newPassword: string = '';
  confirmPassword: string = '';
  errorMessage: string = '';
  successMessage: string = '';

  constructor(
    private route: ActivatedRoute,
    private http: HttpClient,
    private router: Router,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {
    this.route.queryParams.subscribe(params => {
      this.token = params['token'];
      if (!this.token) {
        this.errorMessage = this.translate.instant('RESET_PASSWORD.ERR_INVALID_LINK');
      }
    });
  }

  resetPassword(): void {
    this.errorMessage = '';
    this.successMessage = '';

    if (!this.newPassword || !this.confirmPassword) {
      this.errorMessage = this.translate.instant('RESET_PASSWORD.ERR_FIELDS');
      return;
    }

    if (this.newPassword !== this.confirmPassword) {
      this.errorMessage = this.translate.instant('RESET_PASSWORD.ERR_MISMATCH');
      return;
    }

    const payload = {
      token: this.token,
      new_password: this.newPassword
    };

    this.http.post<any>(apiUrl('/reset-password'), payload).subscribe({
      next: response => {
        this.successMessage = response.message;
        setTimeout(() => this.router.navigate(['/login']), 3000);
      },
      error: err => {
        this.errorMessage = err.error?.error || this.translate.instant('RESET_PASSWORD.ERR_GENERIC');
      }
    });
  }
}
