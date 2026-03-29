import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { BehaviorSubject, Observable } from 'rxjs';
import { apiUrl } from './api-url';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private connectedSubject = new BehaviorSubject<boolean>(this.hasUserSession());
  private roleSubject = new BehaviorSubject<string>(this.getRole());
  private prenomSubject = new BehaviorSubject<string>(this.getPrenom());

  isConnected$ = this.connectedSubject.asObservable();
  role$ = this.roleSubject.asObservable();
  prenom$ = this.prenomSubject.asObservable();

  constructor(private http: HttpClient, private router: Router) {}

  private getUserData(): any {
    const local = localStorage.getItem('userData');
    const session = sessionStorage.getItem('userData');
    return local ? JSON.parse(local) : (session ? JSON.parse(session) : {});
  }

  private hasUserSession(): boolean {
    const uid =
      localStorage.getItem('userID') || sessionStorage.getItem('userID');
    // JWT peut être en cookie HttpOnly (pas dans le stockage) : la session UI repose sur userID
    return !!uid;
  }

  getAccessToken(): string {
    return (
      localStorage.getItem('access_token') ||
      sessionStorage.getItem('access_token') ||
      ''
    );
  }

  private getPrenom(): string {
    return this.getUserData().prenom || '';
  }

  login(email: string, password: string): Observable<any> {
  return this.http.post<any>(apiUrl('/login'), { email, password }, {
    headers: { 'Content-Type': 'application/json' }
  });
}

  logout(): void {
    const token = this.getAccessToken();
    if (token) {
      this.http.post(apiUrl('/api/logout'), {}).subscribe({
          next: () => this.clearSessionAndRedirect(),
          error: () => this.clearSessionAndRedirect(),
        });
    } else {
      this.clearSessionAndRedirect();
    }
  }

  private clearSessionAndRedirect(): void {
    localStorage.clear();
    sessionStorage.clear();
    this.updateConnectionStatus();
    this.router.navigate(['/login']);
  }

  isAuthenticated(): boolean {
    return this.hasUserSession();
  }

  updateConnectionStatus(): void {
    this.connectedSubject.next(this.hasUserSession());
    this.roleSubject.next(this.getRole());
    this.prenomSubject.next(this.getPrenom());
  }

  getUserID(): string {
    return this.getUserData().userID || '';
  }

  getRole(): string {
    return localStorage.getItem('role') || sessionStorage.getItem('role') || '';
  }

  isLoggedIn(): boolean {
    return this.hasUserSession();
  }

  getCurrentUser(): any {
    return this.getUserData();
  }

  getUserProfile(): any {
    const profile = localStorage.getItem('profile');
    return profile ? JSON.parse(profile) : {};
  }

  setUserSession(userData: any): void {
    localStorage.setItem('userID', userData.userID);
    localStorage.setItem('role', userData.role);
    localStorage.setItem('userData', JSON.stringify(userData));
    if (userData.profil) {
      localStorage.setItem('profile', JSON.stringify(userData.profil));
    }

    this.updateConnectionStatus();
  }
}