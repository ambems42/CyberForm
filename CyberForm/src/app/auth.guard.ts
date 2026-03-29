import { Injectable } from '@angular/core';
import { CanActivate, Router } from '@angular/router';
import { AuthService } from './auth.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(private router: Router, private authService: AuthService) {}

  canActivate(): boolean {
    const userID = localStorage.getItem('userID') || sessionStorage.getItem('userID');

    if (userID) {
      return true;
    } else {
      this.router.navigate(['/login']);
      return false;
    }
  }
}
