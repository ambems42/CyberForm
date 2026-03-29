import { Component, OnInit } from '@angular/core';
import { QuizService, TrainingLearningSummary, TrainingQualityMetrics } from '../quiz.service';
import { AuthService } from '../auth.service';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { TranslateService } from '@ngx-translate/core';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-user',
  templateUrl: './user.component.html',
  styleUrls: ['./user.component.css']
})
export class UserComponent implements OnInit {

  userID = '';
  nom = '';
  prenom = '';

  user: any = null;

  roleAssets: string[] = [];
  assetsDetails: any[] = [];

  historique: any[] = [];
  training: string = '';
  lastQuiz: any = null;

  result: any = null;
  quiz: any[] = [];
  quizSubmitted = false;

  quizType: 'pre' | 'post' = 'pre';

  postQuizRequired = false;

  selectedQuiz: any = null;
  selectedQuizType: 'pre' | 'post' = 'pre';

  latestQuiz: any = null;

  activeSection: string = 'user';

  formation: string = '';
  /** Dernière réponse /generate_training (affichage futur / cohérence avec formation) */
  lastTrainingQuality: TrainingQualityMetrics | null = null;
  lastTrainingLearningSummary: TrainingLearningSummary | null = null;

  SEUIL_RISQUE = 70;

  // Notifications d'évaluation
  evaluationDaysLeft: number | null = null;
  evaluationSoon = false;
  evaluationToday = false;

  constructor(
    private quizService: QuizService,
    private auth: AuthService,
    private http: HttpClient,
    private router: Router,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {

    const storageUser =
      localStorage.getItem('userData') || sessionStorage.getItem('userData') || '{}';
    const userData = JSON.parse(storageUser);

    this.userID = userData.userID || '';
    this.nom = userData.nom || '';
    this.prenom = userData.prenom || '';

    if (!this.userID) {
      console.error('Utilisateur non connecté');
      this.router.navigate(['/login']);
      return;
    }

    const tempResult = localStorage.getItem('quiz_result');
    if (tempResult) {
      this.result = JSON.parse(tempResult);
    }

    this.activeSection = 'user';

    this.loadUserData();
  }

  setSection(section: string): void {

    if (this.postQuizRequired && section === 'editprofile') {
      this.activeSection = 'formation';
      return;
    }

    if (section === 'quiz') {
      localStorage.setItem('quizType', this.quizType);
    }

    this.activeSection = section;
  }

  /** Affiche « Mon espace » et fait défiler jusqu'au bloc des dates (prochaine évaluation, etc.). */
  goToEvaluationDates(): void {
    this.setSection('user');
    setTimeout(() => {
      const el =
        document.getElementById('user-calendar-dates') ||
        document.querySelector('.calendar-box');
      el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 150);
  }

  private normalizeDates(u: any) {

    if (!u) return;

    const fields = [
      'lastEvaluationDate',
      'nextEvaluationDate',
      'lastTrainingDate',
      'nextTrainingDate',
      'lastQuizDate'
    ];

    for (const key of fields) {

      const v = u[key];

      if (v && typeof v === 'object' && '$date' in v) {
        u[key] = v.$date;
      }
    }
  }

  loadUserData(): void {

    this.http
      .get<any>(apiUrl(`/api/user_with_history/${this.userID}`))
      .subscribe({

        next: (res) => {

          this.user = res.profile ?? res.user ?? res;

          this.normalizeDates(this.user);

          if (this.user && typeof this.user === 'object') {
            (this.user as Record<string, unknown>)['mitre_exposure'] =
              res.mitre_exposure ?? null;
          }

          // Notification d'évaluation à partir de nextEvaluationDate
          const nextEvalRaw = this.user?.nextEvaluationDate
            ? new Date(this.user.nextEvaluationDate)
            : null;
          this.evaluationDaysLeft = null;
          this.evaluationSoon = false;
          this.evaluationToday = false;

          if (nextEvalRaw && !isNaN(nextEvalRaw.getTime())) {
            const evalDate = new Date(nextEvalRaw);
            const today = new Date();
            evalDate.setHours(0, 0, 0, 0);
            today.setHours(0, 0, 0, 0);
            const diffDays = Math.round(
              (evalDate.getTime() - today.getTime()) / (1000 * 60 * 60 * 24)
            );
            this.evaluationDaysLeft = diffDays;
            this.evaluationToday = diffDays === 0;
            this.evaluationSoon = diffDays > 0 && diffDays <= 7;
          }

          this.historique = Array.isArray(res.quiz_history)
            ? res.quiz_history
            : [];

          this.training = res.lastTrainingContent ?? '';

          if (this.historique.length) {

            this.lastQuiz = this.historique
              .slice()
              .sort(
                (a, b) =>
                  new Date(b.date).getTime() - new Date(a.date).getTime()
              )[0];

          } else {

            this.lastQuiz = null;
          }

          const lastType = this.user.lastQuizType ?? this.lastQuiz?.quiz_type;

          const objectifAtteint =
            this.user.objectifAtteint ??
            this.lastQuiz?.objectifAtteint ??
            false;

          this.quizType =
            lastType === 'pre' && !objectifAtteint
              ? 'post'
              : 'pre';

          this.postQuizRequired =
            Boolean(lastType === 'pre' && !objectifAtteint);

          if (this.postQuizRequired && this.activeSection === 'editprofile') {
            this.activeSection = 'formation';
          }

          this.filterLatestQuizByType();

          const jobRole = this.user?.jobRole;

          if (jobRole) {
            this.loadRoleAssets(jobRole);
          }
        },

        error: (err) => {
          console.error('Erreur de récupération du profil :', err);
        }
      });
  }

  private loadRoleAssets(jobRole: string): void {

    this.http
      .get<any>(
        apiUrl(`/api/role_assets/${encodeURIComponent(jobRole)}`)
      )
      .subscribe({

        next: (res) => {

          const ids: string[] = res.asset_ids ?? res.assets ?? [];

          this.roleAssets = ids;

          if (!ids.length) {
            this.assetsDetails = [];
            return;
          }

          const params = { ids: ids.join(',') };

          this.http
            .get<any[]>(
              apiUrl('/api/assets_catalog'),
              { params }
            )
            .subscribe({

              next: (assets) => {
                this.assetsDetails = Array.isArray(assets) ? assets : [];
              },

              error: (err) => {
                console.error(
                  'Erreur lors de la récupération des détails des actifs :',
                  err
                );
                this.assetsDetails = [];
              }
            });
        },

        error: (err) => {
          console.error(
            'Erreur lors de la récupération des actifs du rôle :',
            err
          );

          this.roleAssets = [];
          this.assetsDetails = [];
        }
      });
  }

  revoirQuiz(q: any): void {

    if (!q || !q._id) {
      console.error('Quiz sans ID :', q);
      return;
    }

    const id = q._id.$oid ? q._id.$oid : q._id;

    console.log('Navigation vers review-quiz avec id =', id);

    this.router.navigate(['/review-quiz', id]);
  }

  submitQuiz(answers: any[]): void {

    if (!this.userID || !answers.length) return;

    const total_questions = this.quiz.length;

    const payload = {
      answers,
      total_questions,
      userID: this.userID,
      quiz_type: this.quizType,
      profile: this.user
    };

    this.http
      .post<any>(apiUrl('/evaluate'), payload)
      .subscribe({

        next: (res) => {

          this.result = res;

          localStorage.setItem('quiz_result', JSON.stringify(res));

          this.quizSubmitted = true;

          console.log('Résultat du quiz :', res);

          this.loadUserData();

          if (!res.objectifAtteint && this.quizType === 'post') {
            this.generateTraining();
          }
        },

        error: (err) => {
          console.error('Erreur lors de l’évaluation du quiz :', err);
        }
      });
  }

  generateTraining(): void {
    this.quizService
      .generateTraining({
        userID: this.userID,
        profile: this.user,
        quiz_type: this.quizType,
        results: this.result || undefined,
        human_threats: this.getHumanThreatsForTraining(),
      })
      .subscribe({
        next: (res) => {
          alert('Une nouvelle formation vous a été attribuée.');

          console.log('Formation :', res.training);

          this.training = res.training || '';
          this.lastTrainingQuality = res.quality_metrics ?? null;
          this.lastTrainingLearningSummary = res.learning_summary ?? null;

          localStorage.setItem('formation', JSON.stringify(res.training));
          if (res.quality_metrics) {
            localStorage.setItem(
              'formation_quality_metrics',
              JSON.stringify(res.quality_metrics)
            );
          }
          if (res.learning_summary) {
            localStorage.setItem(
              'formation_learning_summary',
              JSON.stringify(res.learning_summary)
            );
          }
        },

        error: (err) => {
          console.error(
            'Erreur lors de la génération de la formation :',
            err
          );
        },
      });
  }

  /** Menaces humaines du profil (même logique que le quiz si besoin). */
  private getHumanThreatsForTraining(): any[] {
    const assets = this.user?.mitre_exposure?.assets || this.user?.assets || [];
    const out: any[] = [];
    if (!Array.isArray(assets)) return out;
    for (const a of assets) {
      const ht = a?.human_techniques;
      const list = Array.isArray(ht) ? ht : ht ? [ht] : [];
      for (const t of list) {
        if (t && typeof t === 'object') out.push(t);
      }
    }
    return out;
  }

  getRiskBadge(score: number): string {

    if (score == null) return '';

    if (score < 30) return 'low';

    if (score < 70) return 'medium';

    return 'high';
  }

  shouldRetakePostQuiz(): boolean {

    const postQuizzes = this.historique.filter(
      (q) => q.quiz_type === 'post'
    );

    const lastPost = postQuizzes
      .slice()
      .sort(
        (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
      )[0];

    const risk =
      lastPost?.normalized_risk_score ??
      lastPost?.risk_norm_pct ??
      lastPost?.riskNormPct ??
      lastPost?.riskScore ??
      0;

    return !!(lastPost && risk > this.SEUIL_RISQUE);
  }

  filterLatestQuizByType(): void {

    const filtered = this.historique
      .filter((q) => q.quiz_type === this.selectedQuizType)
      .sort(
        (a, b) => new Date(b.date).getTime() - new Date(a.date).getTime()
      );

    this.latestQuiz = filtered.length ? filtered[0] : null;

    console.log("latestQuiz =", this.latestQuiz);
  }

  getNiveauRisque(quiz: any): string {

    const score =
      quiz?.normalized_risk_score ??
      quiz?.risk_norm_pct ??
      quiz?.riskNormPct ??
      quiz?.riskScore ??
      quiz?.risk_score ??
      0;

    if (score < 30) return this.translate.instant('QUIZ.RISK_LEVEL_LOW');

    if (score < 70) return this.translate.instant('QUIZ.RISK_LEVEL_MEDIUM');

    return this.translate.instant('QUIZ.RISK_LEVEL_HIGH');
  }
  
}