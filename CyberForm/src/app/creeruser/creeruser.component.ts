import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { TranslateService } from '@ngx-translate/core';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-creeruser',
  templateUrl: './creeruser.component.html',
  styleUrls: ['./creeruser.component.css']
})
export class CreeruserComponent {
  user = {
    userID: '',
    prenom: '',
    nom: '',
    email: '',
    password: '',
    role: 'utilisateur',
    profil: {
      jobRole: '',
      qualifications: ['', '', ''],
      keyResponsibilities: ['']
    },
    asset_profile: {
      technological_assets: [
        {
          name: '',
          usage: '',
          software: ['']
        }
      ],
      devices: [
        {
          device_type: '',
          brand: '',
          OS: '',
          role: ''
        }
      ]
    },
    impact_analysis: {
      confidentialité: { niveau: '', score: 0 },
      intégrité: { niveau: '', score: 0 },
      disponibilité: { niveau: '', score: 0 },
      impact_total: 1
    },
    user_activity_log: [
      {
        date: '',
        activity: '',
        potential_risk: ''
      }
    ],
    user_score: 0,
    risk_score: 100
  };

  confirmPassword = '';
  showPasswords = false;

  successMessage = '';
  errorMessage = '';
  isLoading = false;

  private strongPasswordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

  constructor(
    private http: HttpClient,
    private router: Router,
    private translate: TranslateService
  ) {}

  addSoftware(index: number): void {
    this.user.asset_profile.technological_assets[index].software.push('');
  }

  addTechnology(): void {
    this.user.asset_profile.technological_assets.push({
      name: '',
      usage: '',
      software: ['']
    });
  }

  addDevice(): void {
    this.user.asset_profile.devices.push({
      device_type: '',
      brand: '',
      OS: '',
      role: ''
    });
  }

  addActivity(): void {
    this.user.user_activity_log.push({
      date: '',
      activity: '',
      potential_risk: ''
    });
  }

  addResponsibility(): void {
    this.user.profil.keyResponsibilities.push('');
  }

  createUser(): void {
    this.successMessage = '';
    this.errorMessage = '';

    if (this.user.password !== this.confirmPassword) {
      this.errorMessage = this.translate.instant('CREERUSER.ERR_PASSWORD_MISMATCH');
      return;
    }

    if (!this.strongPasswordRegex.test(this.user.password)) {
      this.errorMessage = this.translate.instant('CREERUSER.ERR_PASSWORD_POLICY');
      return;
    }

    this.isLoading = true;

    this.http.post(apiUrl('/api/create_user'), this.user).subscribe({
      next: () => {
        this.successMessage = this.translate.instant('CREERUSER.SUCCESS');
        this.isLoading = false;
        setTimeout(() => this.router.navigate(['/admin']), 2000);
        this.resetForm();
      },
      error: err => {
        this.isLoading = false;
        this.errorMessage =
          err.error?.error || this.translate.instant('CREERUSER.ERR_GENERIC');
      }
    });
  }

  resetForm(): void {
    this.user = {
      userID: '',
      prenom: '',
      nom: '',
      email: '',
      password: '',
      role: 'utilisateur',
      profil: {
        jobRole: '',
        qualifications: ['', '', ''],
        keyResponsibilities: ['']
      },
      asset_profile: {
        technological_assets: [
          {
            name: '',
            usage: '',
            software: ['']
          }
        ],
        devices: [
          {
            device_type: '',
            brand: '',
            OS: '',
            role: ''
          }
        ]
      },
      impact_analysis: {
        confidentialité: { niveau: '', score: 0 },
        intégrité: { niveau: '', score: 0 },
        disponibilité: { niveau: '', score: 0 },
        impact_total: 1
      },
      user_activity_log: [
        {
          date: '',
          activity: '',
          potential_risk: ''
        }
      ],
      user_score: 0,
      risk_score: 100
    };
  }
}
