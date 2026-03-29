import { Component, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { AuthService } from '../auth.service';
import { Router } from '@angular/router';
import { TranslateService } from '@ngx-translate/core';
import { apiUrl } from '../api-url';

@Component({
  selector: 'app-history-user',
  templateUrl: './history-user.component.html',
  styleUrl: './history-user.component.css'
})
export class HistoryUserComponent implements OnInit {
  quizHistory: any[] = [];
  errorMessage = '';
  userID = '';

  constructor(
    private http: HttpClient,
    private auth: AuthService,
    private router: Router,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {
    this.userID = this.auth.getUserID();
    this.http.get<any>(apiUrl(`/api/user_with_history/${this.userID}`)).subscribe({
      next: res => {
        this.quizHistory = res.quiz_history;
      },
      error: () => {
        this.errorMessage = this.translate.instant('HISTORY_USER_PAGE.LOAD_ERROR');
      }
    });
  }

  revoirQuiz(quiz: any): void {
    this.router.navigate(['/review-quiz', quiz._id]);
  }
}
