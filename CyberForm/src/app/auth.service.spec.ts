import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  getUserID(): string {
    try {
      const profile = JSON.parse(localStorage.getItem('profile') || '{}');
      return typeof profile.userID === 'string' ? profile.userID : '';
    } catch (error) {
      console.error('Erreur de parsing du profil localStorage :', error);
      return '';
    }
  }

  getUserRole(): string {
    try {
      const profile = JSON.parse(localStorage.getItem('profile') || '{}');
      return typeof profile.role === 'string' ? profile.role : '';
    } catch (error) {
      console.error('Erreur de parsing du profil localStorage :', error);
      return '';
    }
  }

  isLoggedIn(): boolean {
    const userID = this.getUserID();
    return userID !== '';
  }

  logout(): void {
    localStorage.removeItem('profile');
    localStorage.removeItem('userData');
    window.location.href = '/login';
  }
}
