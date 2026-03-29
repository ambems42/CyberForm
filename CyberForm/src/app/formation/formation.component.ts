import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from '../auth.service';
import { HttpClient } from '@angular/common/http';
import { TranslateService } from '@ngx-translate/core';
import {
  LastTrainingMeta,
  TrainingLearningSummary,
  TrainingQualityMetrics,
} from '../quiz.service';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-formation',
  templateUrl: './formation.component.html',
  styleUrls: ['./formation.component.css']
})
export class FormationComponent implements OnInit {
  formation: string = '';
  history: any[] = [];
  today: Date = new Date();
  @Output() retourEvent = new EventEmitter<void>();
  postQuizRecommended = false;
  /** Métadonnées dernière formation (Mongo + API) */
  lastTrainingMeta: LastTrainingMeta | null = null;
  trainingQuality: TrainingQualityMetrics | null = null;
  trainingLearningSummary: TrainingLearningSummary | null = null;
  private userID: string = '';

  constructor(
    private auth: AuthService,
    private http: HttpClient,
    private router: Router,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {
    this.userID = this.auth.getUserID();
    this.hydrateTrainingMetaFromStorage();
    this.http.get<any>(apiUrl(`/api/user_with_history/${this.userID}`)).subscribe({
      next: res => {
        this.formation =
          res.lastTrainingContent || this.translate.instant('FORMATION_PAGE.HTML_NONE');
        this.history = res.training_history || res.trainingHistory || [];
        this.lastTrainingMeta = res.lastTrainingMeta ?? null;
        if (this.lastTrainingMeta?.quality_metrics != null) {
          this.trainingQuality = this.lastTrainingMeta.quality_metrics;
        }
        if (this.lastTrainingMeta?.learning_summary != null) {
          this.trainingLearningSummary = this.lastTrainingMeta.learning_summary;
        }

        const profile = res.profile || {};
        const lastQuizType = profile.lastQuizType || null;
        const objectifAtteint = !!profile.objectifAtteint;
        this.postQuizRecommended = Boolean(lastQuizType === 'pre' && !objectifAtteint && !!this.formation);
      },
      error: err => {
        console.error('Erreur récupération formation :', err);
        this.formation = this.translate.instant('FORMATION_PAGE.HTML_ERR');
      }
    });
  }

  /** Fallback session (génération récente depuis le quiz sans rechargement API). */
  private hydrateTrainingMetaFromStorage(): void {
    try {
      const qm = localStorage.getItem('formation_quality_metrics');
      const ls = localStorage.getItem('formation_learning_summary');
      if (qm && !this.trainingQuality) {
        this.trainingQuality = JSON.parse(qm) as TrainingQualityMetrics;
      }
      if (ls && !this.trainingLearningSummary) {
        this.trainingLearningSummary = JSON.parse(ls) as TrainingLearningSummary;
      }
    } catch {
      /* ignore */
    }
  }

  startPostQuizFromFormation(): void {
    if (!this.userID) {
      this.userID = this.auth.getUserID();
    }
    localStorage.setItem('quizType', 'post');
    this.router.navigate(['/quiz']);
  }

  printTraining(): void {
    const content = document.getElementById('trainingContent');
    if (!content) return;

    const printWindow = window.open('', '_blank');
    if (printWindow) {
      const documentContent = `
        <html>
          <head>
            <title>${this.translate.instant('FORMATION_PAGE.PRINT_DOC_TITLE')}</title>
            <style>
              body {
                font-family: Arial, sans-serif;
                padding: 30px;
                color: #333;
                line-height: 1.6;
              }
              .logo {
                max-width: 120px;
                margin-bottom: 10px;
                display: block;
              }
              h2 {
                text-align: center;
                color: #003366;
                margin-bottom: 20px;
              }
              .date {
                text-align: right;
                font-size: 0.9rem;
                color: #666;
                margin-bottom: 30px;
              }
            </style>
          </head>
          <body>
            ${content.innerHTML}
          </body>
        </html>
      `;

      printWindow.document.write(documentContent);
      printWindow.document.close();

      printWindow.onload = () => {
        const logo = printWindow.document.getElementById('logo') as HTMLImageElement;
        if (!logo) {
          console.warn("Logo introuvable.");
          printWindow.print();
          printWindow.close();
          return;
        }

        if (logo.complete) {
          printWindow.print();
          printWindow.close();
        } else {
          logo.onload = () => {
            printWindow.print();
            printWindow.close();
          };
          logo.onerror = () => {
            console.warn("Erreur de chargement du logo.");
            printWindow.print();
            printWindow.close();
          };
        }
      };
    }
  }
}
