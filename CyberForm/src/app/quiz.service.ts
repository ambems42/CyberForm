import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { apiUrl } from './api-url';

@Injectable({
  providedIn: 'root'
})
export class QuizService {
  constructor(private http: HttpClient) {}

  /**
   * Génère un quiz (aligné sur Flask : POST /generate_quiz, pas /api/generate_quiz).
   */
  generateQuiz(payload: {
    userID?: string;
    profile: any;
    quiz_type: 'pre' | 'post';
    human_only?: boolean;
    human_threats?: any[];
    required_scores?: any[];
  }): Observable<any> {
    return this.http.post<any>(apiUrl('/generate_quiz'), payload);
  }

  /** Évaluation : POST /evaluate (pas /api/evaluate) */
  evaluateQuiz(data: any): Observable<any> {
    return this.http.post<any>(apiUrl('/evaluate'), data);
  }

  // Sauvegarder un résultat de quiz en base MongoDB
  saveQuizResult(userID: string, quizType: 'pre' | 'post', result: any): Observable<any> {
    return this.http.post<any>(apiUrl('/api/save_quiz_result'), {
      userID,
      type: quizType,
      date: new Date().toISOString(),
      result
    });
  }

  /**
   * Génère une formation (POST /generate_training).
   * Réponse typique : training, quality_metrics, training_blueprint, learning_summary
   */
  generateTraining(data: {
    userID: string;
    profile: any;
    quiz_type?: 'pre' | 'post';
    results?: any;
    human_threats?: any[];
  }): Observable<GenerateTrainingResponse> {
    return this.http.post<GenerateTrainingResponse>(apiUrl('/generate_training'), data);
  }

  // Récupérer un quiz par son identifiant MongoDB
  getQuizById(id: string): Observable<any> {
    return this.http.get<any>(apiUrl(`/api/quiz/${id}`));
  }

  // Récupérer la liste des utilisateurs (encore en JSON local pour l’instant)
  getUsers(): Observable<any[]> {
    return this.http.get<any[]>('assets/data.json');
  }

  // Récupérer les infos d’un utilisateur + son historique de quiz
  getUserWithHistory(userID: string): Observable<any> {
    return this.http.get<any>(apiUrl(`/api/user_with_history/${userID}`));
  }

  // Obtenir les statistiques globales des utilisateurs
  getStats(): Observable<any> {
    return this.http.get<any>(apiUrl('/api/statistics'));
  }

  // Récupérer les actifs d’un utilisateur
  getUserAssets(userID: string): Observable<any> {
    const url = apiUrl(`/api/user/${userID}/assets`);
    console.log('URL getUserAssets =', url);
    return this.http.get<any>(url);
  }

  /**
   * Métriques qualité des quiz générés (Mongo quiz_genere), pour admin / reporting.
   * GET /api/quiz_quality_metrics
   */
  getQuizQualityMetrics(options?: {
    limit?: number;
    userID?: string;
  }): Observable<{ items: QuizQualityMetricItem[]; count: number }> {
    let params = new HttpParams();
    if (options?.limit != null) {
      params = params.set('limit', String(options.limit));
    }
    const uid = options?.userID?.trim();
    if (uid) {
      params = params.set('userID', uid);
    }
    return this.http.get<{ items: QuizQualityMetricItem[]; count: number }>(
      apiUrl('/api/quiz_quality_metrics'),
      { params }
    );
  }

  /**
   * URL du CSV export (GET /api/quiz_quality_metrics.csv) — ouvrir dans un nouvel onglet ou <a download>.
   */
  buildQuizQualityMetricsCsvUrl(options?: { limit?: number; userID?: string }): string {
    const path = apiUrl('/api/quiz_quality_metrics.csv');
    const u = path.startsWith('http')
      ? new URL(path)
      : new URL(path, typeof window !== 'undefined' ? window.location.origin : 'http://localhost:4200');
    if (options?.limit != null) {
      u.searchParams.set('limit', String(options.limit));
    }
    const uid = options?.userID?.trim();
    if (uid) {
      u.searchParams.set('userID', uid);
    }
    return u.toString();
  }
}

/** Une ligne renvoyée par GET /api/quiz_quality_metrics */
export interface QuizQualityMetricItem {
  quiz_id: string;
  userID?: string;
  quiz_type?: string;
  date?: string;
  quality_metrics?: Record<string, unknown>;
}

/** Élément learning_summary.techniques (formation) */
export interface TrainingTechniqueSummary {
  technique_id?: string;
  technique_name?: string;
  quality_score?: number | null;
}

/** Résumé pédagogique renvoyé avec la formation */
export interface TrainingLearningSummary {
  quiz_type?: string;
  techniques?: TrainingTechniqueSummary[];
  progress_note?: string;
  post_test_alignment_note?: string;
}

/** Agrégat quality_metrics formation (module + global) */
export interface TrainingQualityMetrics {
  quality_score?: number;
  quality_threshold?: number;
  quality_below_threshold?: boolean;
  modules?: Array<Record<string, unknown>>;
  gpt_validator_enabled?: boolean;
  quality_attempts_note?: string;
}

export interface GenerateTrainingResponse {
  training?: string;
  content?: string;
  quality_metrics?: TrainingQualityMetrics;
  training_blueprint?: unknown[];
  learning_summary?: TrainingLearningSummary;
  message?: string;
  training_id?: string;
}

/** Dernière formation : GET /api/user_with_history/:id */
export interface LastTrainingMeta {
  training_id?: string;
  quiz_type?: string;
  date?: string;
  quality_metrics?: TrainingQualityMetrics;
  learning_summary?: TrainingLearningSummary;
  training_blueprint?: unknown[];
}
