import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { throwError } from 'rxjs';
import { apiUrl } from './api-url';

@Injectable({
  providedIn: 'root'
})
export class UserService {

  constructor(private http: HttpClient) { }

  getUserScores() {
    return this.http.get<any[]>(apiUrl('/api/user-scores'));
  }

  generateProfileRisk(userID: string, profile: any) {
    return this.http.post<any>(apiUrl('/generate_profile_risk'), {
      userID,
      profile,
    });
  }

  getUserAssets(userID: string) {
    if (!userID) {
      return throwError(() => new Error('userID manquant'));
    }
    return this.http.get<{ userID: string; devices: any[]; technological_assets: any[] }>(
      apiUrl(`/api/user/${encodeURIComponent(userID)}/assets`)
    );
  }

}
