import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { TranslateService } from '@ngx-translate/core';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-review-quiz',
  templateUrl: './review-quiz.component.html',
  styleUrls: ['./review-quiz.component.css']
})
export class ReviewQuizComponent implements OnInit {
  quizId: string = '';
  quiz: any = null;
  errorMessage: string = '';
  loading: boolean = true;

  constructor(
    private route: ActivatedRoute,
    private http: HttpClient,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {
    this.quizId = this.route.snapshot.paramMap.get('id') || '';

    if (!this.quizId) {
      this.errorMessage = this.translate.instant('REVIEW_QUIZ.ERR_NO_ID');
      this.loading = false;
      return;
    }

    this.fetchQuiz();
  }

  fetchQuiz(): void {
    this.http.get<any>(apiUrl(`/api/quiz/${this.quizId}`)).subscribe({
      next: (res) => {
        this.quiz = this.normalizeQuiz(res);
        this.loading = false;
        console.log('Quiz chargé :', this.quiz);
      },
      error: (err) => {
        console.error('Erreur chargement quiz :', err);
        this.errorMessage = this.translate.instant('REVIEW_QUIZ.ERR_LOAD');
        this.loading = false;
      }
    });
  }

  normalizeQuiz(data: any): any {
    if (!data) return null;

    return {
      ...data,
      date: data?.date || data?.createdAt || new Date(),
      user_score: this.toNumber(data?.user_score ?? data?.score ?? 0),
      total_questions: this.toNumber(data?.total_questions ?? data?.totalQuestions ?? 0),
      quiz_type: data?.quiz_type || data?.quizType || 'pre',
      normalized_risk_score: this.toNumber(
        data?.normalized_risk_score ??
        data?.riskNormPct ??
        data?.riskScore ??
        data?.risk_score ??
        0
      ),
      vulnerability_score: this.toNumber(data?.vulnerability_score ?? 0),
      answers: Array.isArray(data?.answers)
        ? data.answers.map((a: any) => ({
            scenario: a?.scenario || '',
            question: a?.question || '',
            choices: Array.isArray(a?.choices) ? a.choices : [],
            correct_answer: a?.correct_answer || a?.correctAnswer || '',
            selected: a?.selected || a?.user_answer || ''
          }))
        : []
    };
  }

  toNumber(value: any): number {
    const n = Number(value);
    return isNaN(n) ? 0 : n;
  }

  isCorrect(answer: any): boolean {
    const user = (answer?.selected || '').toString().trim().toLowerCase();
    const correct = (answer?.correct_answer || '').toString().trim().toLowerCase();

    if (!user || !correct) {
      return false;
    }

    return user === correct;
  }

  get isAdmin(): boolean {
    const profile = JSON.parse(localStorage.getItem('profile') || '{}');
    const role = profile?.role || profile?.basic_info?.role || '';
    return role === 'admin';
  }
  getDisplayedRisk(): number {
  if (!this.quiz) return 0;

  return Number(
    this.quiz.risk_norm_pct ??
    this.quiz.normalized_risk_score ??
    this.quiz.riskNormPct ??
    this.quiz.riskScore ??
    0
  );
}
}