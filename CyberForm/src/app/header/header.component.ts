import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { TranslateService } from '@ngx-translate/core';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit {
  selectedLanguage = 'fr';
  isConnected = false;
  role = '';
  prenom = '';

  constructor(
    private router: Router,
    private translate: TranslateService,
    private auth: AuthService
  ) {
    this.translate.addLangs(['fr', 'en', 'es']);
    this.translate.setDefaultLang('fr');

    const savedLang = localStorage.getItem('lang');
    const browserLang = (this.translate.getBrowserLang() || '').split('-')[0];
    const supported = ['fr', 'en', 'es'];

    this.selectedLanguage =
      savedLang && supported.includes(savedLang)
        ? savedLang
        : supported.includes(browserLang)
          ? browserLang
          : 'fr';
    this.translate.use(this.selectedLanguage);
  }

  ngOnInit(): void {
    // Abonnement aux changements de connexion et rôle
    this.auth.isConnected$.subscribe(status => {
      this.isConnected = status;
    });

    this.auth.role$.subscribe(r => {
      this.role = r;
    });

    // Récupération prénom
    const user = JSON.parse(localStorage.getItem('userData') || '{}');
    this.prenom = user?.prenom || '';
  }

  switchLanguage(): void {
    this.translate.use(this.selectedLanguage);
    localStorage.setItem('lang', this.selectedLanguage);
  }

  logout(): void {
    this.auth.logout();
    this.isConnected = false;
    this.role = '';
    this.prenom = '';
    this.router.navigate(['/login']);
  }
  menuOpen = false;

toggleMenu() {
  this.menuOpen = !this.menuOpen;
}

}
