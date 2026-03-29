import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../auth.service';
import { HttpClient } from '@angular/common/http';
import { TranslateService } from '@ngx-translate/core';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  email = '';
  password = '';
  errorMessage = '';
  rememberMe: boolean = false;
  showPassword: boolean = false;

  constructor(
    private authService: AuthService,
    private http: HttpClient,
    private router: Router,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {
    // On regarde s'il y a déjà une session
    const role = localStorage.getItem('role') || sessionStorage.getItem('role');

    if (role === 'admin') {
      this.router.navigate(['/admin']);
    } else if (role === 'utilisateur') {
      this.router.navigate(['/user']);
    } 
    // IMPORTANT : ne PAS mettre de else ici,
    // sinon tu affiches une erreur dès l'arrivée sur la page,
    // alors que l'utilisateur n'a encore rien fait.
  }

  login(): void {
    this.errorMessage = '';

    this.authService.login(this.email, this.password).subscribe({
      next: res => {
        const { userID, role, access_token } = res;

        // On nettoie d'abord les deux stockages
        localStorage.removeItem('userID');
        localStorage.removeItem('role');
        localStorage.removeItem('profile');
        localStorage.removeItem('userData');
        localStorage.removeItem('access_token');
        sessionStorage.removeItem('userID');
        sessionStorage.removeItem('role');
        sessionStorage.removeItem('profile');
        sessionStorage.removeItem('userData');
        sessionStorage.removeItem('access_token');

        // Choix du stockage en fonction de "Se souvenir de moi"
        const storage = this.rememberMe ? localStorage : sessionStorage;

        storage.setItem('userID', userID);
        storage.setItem('role', role);
        if (access_token) {
          storage.setItem('access_token', access_token);
        }

        // Récupérer le profil complet
        this.http.get<any>(apiUrl(`/api/user_with_history/${userID}`))
          .subscribe({
            next: (data) => {
              const { nom, prenom } = data.profile;

              storage.setItem('profile', JSON.stringify(data.profile));
              storage.setItem('userData', JSON.stringify({
                userID,
                nom,
                prenom,
                role
              }));

              console.log('Connexion réussie :', JSON.parse(storage.getItem('userData') || '{}'));

              this.authService.updateConnectionStatus();

              // Redirection selon le rôle
              if (role === 'admin') {
                this.router.navigate(['/admin']);
              } else if (role === 'utilisateur') {
                this.router.navigate(['/user']);
              } else {
                this.errorMessage = this.translate.instant('LOGIN.ERR_UNKNOWN_ROLE');
              }
            },
            error: () => {
              this.errorMessage = this.translate.instant('LOGIN.ERR_PROFILE_LOAD');
            }
          });
      },
      error: (err) => {
        this.errorMessage =
          err.error?.error || this.translate.instant('LOGIN.ERR_CONNECTION');
      }
    });
  }
}
