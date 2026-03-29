import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { apiUrl } from './api-url';

@Injectable({
  providedIn: 'root'
})
export class ProfileService {
  constructor(private http: HttpClient) {}

  // Obtenir tous les profils
  getProfiles(): Observable<any[]> {
    return this.http.get<any[]>(apiUrl('/api/profiles'));
  }

  // Obtenir un profil avec historique
  getUserWithHistory(userID: string): Observable<any> {
    return this.http.get<any>(apiUrl(`/api/user_with_history/${userID}`));
  }

  // Mettre à jour le prénom et nom d'un profil
  updateProfile(userID: string, firstName: string, lastName: string): Observable<any> {
    return this.http.post(apiUrl('/api/update_profile'), {
      userID,
      first_name: firstName,
      last_name: lastName
    });
  }

  // Appeler les statistiques
  getStatistics(): Observable<any> {
    return this.http.get(apiUrl('/api/statistics'));
  }
}
