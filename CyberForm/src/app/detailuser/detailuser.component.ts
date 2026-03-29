import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { LastTrainingMeta, QuizService } from '../quiz.service';

@Component({
  selector: 'app-detailuser',
  templateUrl: './detailuser.component.html',
  styleUrls: ['./detailuser.component.css']
})
export class DetailuserComponent implements OnInit {

  userID: string = '';
  user: any = null;
  formation: string | null = null;
  quizHistory: any[] = [];
  quizPre: any[] = [];
  quizPost: any[] = [];
  quizType: 'pre' | 'post' = 'pre';
  lastQuiz: any = null;
  userAssets: any[] = [];
  mitreExposure: any = null;
  trainingHistory: any[] = [];
  expandedTrainingId: string | null = null;
  /** Dernière entrée Mongo trainings (qualité + résumé pédagogique) */
  lastTrainingMeta: LastTrainingMeta | null = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private quizService: QuizService
  ) {}

  ngOnInit(): void {
    this.userID = this.route.snapshot.paramMap.get('userID') || '';

    if (this.userID) {
      this.quizService.getUserWithHistory(this.userID).subscribe({
        next: (res: any) => {
          this.user = {
            ...res.profile,
            profil: res.profile?.profil ?? {},
            asset_profile: res.asset_profile ?? {},
            user_score: res.profile?.user_score ?? 0,
            risk_score: res.profile?.risk_score ?? 0,
            objectifAtteint: res.profile?.objectifAtteint ?? false,
            total_questions: res.profile?.total_questions ?? 0
          };

          this.formation = res.lastTrainingContent ?? null;
          this.lastTrainingMeta = res.lastTrainingMeta ?? null;
          this.quizHistory = res.quiz_history ?? [];
          this.mitreExposure = res.mitre_exposure ?? null;
          this.trainingHistory = res.training_history ?? [];

          this.quizPre = this.quizHistory.filter(q => q.quiz_type === 'pre');
          this.quizPost = this.quizHistory.filter(q => q.quiz_type === 'post');

          if (this.quizHistory.length > 0) {
            this.lastQuiz = this.quizHistory[0];
            this.quizType = this.lastQuiz.quiz_type === 'post' ? 'post' : 'pre';
          }
          this.loadUserAssets();
        },
        error: (err) => console.error('Erreur chargement utilisateur :', err)
      });
    }
  }

  private loadUserAssets(): void {
    if (!this.userID) return;
    this.quizService.getUserAssets(this.userID).subscribe({
      next: (res: any) => {
        this.userAssets = Array.isArray(res) ? res : (res.assets ?? []);
      },
      error: (err) => console.error('Erreur chargement des actifs :', err)
    });
  }

  revoirQuiz(quiz: any): void {
    const id =
      quiz.id ||
      quiz._id?.$oid ||
      quiz._id?.$id ||
      (typeof quiz._id === 'string' ? quiz._id : '');

    const idStr = typeof id === 'string' ? id : String(id || '');
    if (!idStr) return;

    this.router.navigate(['/review-quiz', idStr], { state: { quiz } });
  }

  toggleTrainingContent(trainingId: string): void {
    this.expandedTrainingId = this.expandedTrainingId === trainingId ? null : trainingId;
  }

  getRiskBadge(score: number | null | undefined): string {
    if (score == null || score === undefined) return 'du-risk du-risk--muted';
    if (score < 30) return 'du-risk du-risk--low';
    if (score < 60) return 'du-risk du-risk--med';
    return 'du-risk du-risk--high';
  }

  get hasAssets(): boolean {
    return !!this.userAssets && this.userAssets.length > 0;
  }
}
