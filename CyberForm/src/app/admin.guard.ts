import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { TranslateService } from '@ngx-translate/core';

@Injectable({
  providedIn: 'root'
})
export class AdminGuard implements CanActivate {
  constructor(
    private router: Router,
    private translate: TranslateService
  ) {}

  canActivate(): boolean {
    const local = localStorage.getItem('userData');
    const session = sessionStorage.getItem('userData');
    const userData = local ? JSON.parse(local) : (session ? JSON.parse(session) : {});
    const isAdmin = userData.role === 'admin';

    if (!isAdmin) {
      alert(this.translate.instant('GUARDS.ADMIN_ONLY'));
      this.router.navigate(['/login']);
      return false;
    }

    return true;
  }
}
