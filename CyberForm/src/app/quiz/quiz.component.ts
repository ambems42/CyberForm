import { ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { TranslateService } from '@ngx-translate/core';
import { catchError, of, switchMap, timeout, TimeoutError } from 'rxjs';
import { AuthService } from '../auth.service';
import { Router } from '@angular/router';
import {
  QuizService,
  TrainingLearningSummary,
  TrainingQualityMetrics,
} from '../quiz.service';
import { apiUrl } from '../api-url';

declare var html2pdf: any;

/** Métriques `quality_metrics` renvoyées par POST /generate_quiz */
export interface QuizQualityMetrics {
  quality_score?: number;
  quality_below_threshold?: boolean;
  quality_threshold?: number;
  bloom_coverage?: number;
  technique_unique_count?: number;
  quality_attempts?: number;
  quality_attempts_log?: Array<{ attempt: number; quality_score: number }>;
  bloom_distribution?: Record<string, number>;
  avg_scenario_chars?: number;
  avg_question_chars?: number;
  qcm_count?: number;
  vf_count?: number;
}

@Component({
  selector: 'app-quiz',
  templateUrl: './quiz.component.html',
  styleUrls: ['./quiz.component.css']
})
export class QuizComponent implements OnInit {
  // --- Profil / état principal ---
  profile: any = {};
  quizType: 'pre' | 'post' = 'pre';
  questions: any[] = [];
  answers: string[] = [];
  isSubmitted: boolean[] = [];
  submitted = false;
  result: any = null;
  training = '';
  currentIndex = 0;
  quizFinished = false;
  today = new Date();

  activeSection = 'user';
  afficherFormationManuelle = false;

  // --- Risque / aperçu ---
  profilRisque: any = null;
  /** Avertissement si affichage cache ou échec régénération */
  profilRisqueWarning = '';
  afficherQuiz = false;
  afficherProfilRisque = false;
  messageRisque = '';
  opened?: string;
  overview: any = null;

  // --- Utilisateur ---
  userID = '';
  userData: any = null;
  riskDetailRows: any[] = [];

  // --- Actifs (assets_catalog) ---
  assetsData: any = null;
  assetsLoading = false;
  assetsError: string | null = null;
  devices: any[] = [];
  techAssets: any[] = [];
  roleAssets: string[] = [];
  assetsDetails: any[] = [];
  currentQuizId: string | null = null;
  /** Métriques auto (backend) : score qualité, répartition Bloom, etc. */
  quizQuality: QuizQualityMetrics | null = null;
  /** Pendant /generate_quiz : on vide les questions pour ne pas montrer l'ancien quiz. */
  quizGenerating = false;
  /** Message si la génération échoue (réseau, validation serveur, etc.). */
  quizGenerateError: string | null = null;
  /** Métriques formation (POST /generate_training) */
  trainingQuality: TrainingQualityMetrics | null = null;
  /** Résumé pédagogique + techniques couvertes */
  trainingLearningSummary: TrainingLearningSummary | null = null;
  /**
   * Comparaison technique_id formation vs quiz post (après génération du quiz post).
   */
  postQuizAlignment: {
    formationTechniques: string[];
    quizTechniques: string[];
    missingInQuiz: string[];
    extraInQuiz: string[];
    aligned: boolean;
    noFormationData: boolean;
  } | null = null;
  private draftRestored = false;

  // --- Journal d’activités ---
  activityLog: any[] = [];

  // --- UI helpers ---
  openRows = new Set<string>();

  constructor(
    private http: HttpClient,
    private auth: AuthService,
    private router: Router,
    private quizservice: QuizService,
    private translate: TranslateService,
    private cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    const storedProfile = localStorage.getItem('profile');
    const storedType = localStorage.getItem('quizType');
    const preCompleted = localStorage.getItem('preQuizCompleted');

    if (storedProfile) {
      this.profile = JSON.parse(storedProfile);
    }

    this.userID =
      this.auth?.getUserID?.() ||
      JSON.parse(localStorage.getItem('user') || '{}')?.userID ||
      this.profile?.userID ||
      '';

    this.quizType = storedType === 'post' ? 'post' : 'pre';

    if (!this.userID) {
      console.error('userID manquant : impossible de charger les données utilisateur.');
    } else {
      this.loadUserWithHistory();
      this.loadAssets();

      if (this.profile?.jobRole) {
        this.loadRoleAssets(this.profile.jobRole);
      }
    }

    if (this.quizType === 'pre' && preCompleted === 'true') {
      alert(this.translate.instant('QUIZ.ALERT_PRE_DONE'));
      this.router.navigate(['/user']);
      return;
    }

    this.translate.onLangChange.subscribe(() => this.cdr.detectChanges());

    this.restoreTrainingMetaFromStorage();

    // Restaure le brouillon si l'utilisateur a quitté le quiz avant de terminer
    this.loadDraft();
  }

  private draftPointerKey(type: 'pre' | 'post' = this.quizType): string {
    return `cyberform.quizDraftPointer.${this.userID}.${type}`;
  }

  private draftKey(type: 'pre' | 'post' = this.quizType, quizId: string | null = this.currentQuizId): string {
    const q = (quizId || 'latest').toString();
    return `cyberform.quizDraft.${this.userID}.${type}.${q}`;
  }

  private saveDraft(): void {
    if (!this.userID) return;
    if (!this.afficherQuiz) return;
    if (!this.questions?.length) return;
    if (this.quizFinished) return;

    const payload = {
      userID: this.userID,
      quizType: this.quizType,
      quizId: this.currentQuizId,
      savedAt: new Date().toISOString(),
      currentIndex: this.currentIndex,
      afficherQuiz: this.afficherQuiz,
      questions: this.questions,
      answers: this.answers,
      isSubmitted: this.isSubmitted
    };

    try {
      const key = this.draftKey(this.quizType, this.currentQuizId);
      localStorage.setItem(key, JSON.stringify(payload));
      localStorage.setItem(this.draftPointerKey(this.quizType), key);
    } catch (e) {
      // ignore (quota/locked storage)
    }
  }

  private clearDraft(type: 'pre' | 'post' = this.quizType): void {
    if (!this.userID) return;
    try {
      const pointer = localStorage.getItem(this.draftPointerKey(type));
      if (pointer) localStorage.removeItem(pointer);
      localStorage.removeItem(this.draftPointerKey(type));
    } catch (e) {
      // ignore
    }
  }

  private loadDraft(): void {
    if (!this.userID) return;
    if (this.draftRestored) return;

    const pointer = localStorage.getItem(this.draftPointerKey(this.quizType));
    const raw = pointer ? localStorage.getItem(pointer) : null;
    if (!raw) return;

    try {
      const draft = JSON.parse(raw);
      if (!draft || draft.userID !== this.userID) return;
      if (draft.quizType !== this.quizType) return;

      const questions = Array.isArray(draft.questions) ? draft.questions : [];
      if (!questions.length) return;

      this.currentQuizId = draft.quizId || this.currentQuizId;
      const answers = Array.isArray(draft.answers) ? draft.answers : [];
      const isSubmitted = Array.isArray(draft.isSubmitted) ? draft.isSubmitted : [];

      this.questions = questions;
      this.answers = answers.length === questions.length ? answers : Array(questions.length).fill('');
      this.isSubmitted = isSubmitted.length === questions.length ? isSubmitted : Array(questions.length).fill(false);

      this.afficherQuiz = Boolean(draft.afficherQuiz);
      this.submitted = false;
      this.result = null;
      this.training = '';
      this.quizFinished = false;

      const idx = Number(draft.currentIndex ?? 0);
      this.currentIndex = Math.min(Math.max(idx, 0), questions.length - 1);

      this.draftRestored = true;
      this.quizQuality = null;
    } catch (e) {
      // ignore invalid JSON
    }
  }

  // ================= API: USER + ASSETS =================

  private loadUserWithHistory(): void {
    if (!this.userID) return;

    this.http
      .get<any>(apiUrl(`/api/user_with_history/${encodeURIComponent(this.userID)}`))
      .subscribe({
        next: (res) => {
          this.userData = res || {};
          this.activityLog = Array.isArray(res?.user_activity_log)
            ? res.user_activity_log
            : [];

          if (!this.assetsData && res?.asset_profile) {
            this.assetsData = res.asset_profile;
            this.devices = this.assetsData?.devices ?? [];
            this.techAssets = this.assetsData?.technological_assets ?? [];
          }

          this.syncProfileAndTrainingFromHistory(res);

          const jobRole =
            this.profile?.jobRole ||
            res?.profil?.jobRole ||
            res?.profile?.jobRole;

          if (jobRole && !this.roleAssets.length) {
            this.profile.jobRole = jobRole;
            this.loadRoleAssets(jobRole);
          }

          // Workflow strict: si le dernier quiz était un pre et que l'objectif n'est pas atteint,
          // on force quizType=post (même si localStorage est incohérent)
          const lastType =
            res?.profile?.lastQuizType ||
            res?.profile?.lastQuiz?.quiz_type ||
            res?.profile?.lastQuizType;
          const objectifAtteint = res?.profile?.objectifAtteint ?? false;
          if (lastType === 'pre' && objectifAtteint === false) {
            this.quizType = 'post';
            localStorage.setItem('quizType', 'post');
          }
        },
        error: (err) => {
          console.error('Erreur /api/user_with_history/:', err);
          this.activityLog = [];
        }
      });
  }

  /**
   * Après un quiz ou un reload : aligne profil local + métadonnées formation sur le serveur.
   */
  private syncProfileAndTrainingFromHistory(res: any): void {
    const p = res?.profile;
    if (p && typeof p === 'object') {
      this.profile = {
        ...this.profile,
        userID: p.userID ?? this.profile.userID,
        jobRole: p.jobRole ?? this.profile.jobRole,
        qualifications: Array.isArray(p.qualifications)
          ? p.qualifications
          : this.profile.qualifications,
        keyResponsibilities: Array.isArray(p.responsibilities)
          ? p.responsibilities
          : Array.isArray((p as { keyResponsibilities?: string[] }).keyResponsibilities)
            ? (p as { keyResponsibilities: string[] }).keyResponsibilities
            : this.profile.keyResponsibilities,
      };
      if (typeof p.objectifAtteint === 'boolean') {
        (this.profile as { objectifAtteint?: boolean }).objectifAtteint =
          p.objectifAtteint;
      }
      try {
        localStorage.setItem('profile', JSON.stringify(this.profile));
      } catch {
        /* ignore */
      }
    }

    const meta = res?.lastTrainingMeta;
    if (meta && (meta.learning_summary || meta.quality_metrics)) {
      this.persistTrainingMeta({
        quality_metrics: meta.quality_metrics,
        learning_summary: meta.learning_summary,
      });
    }
  }

  private loadAssets(): void {
    this.assetsLoading = true;
    this.assetsError = null;

    if (!this.userID) {
      this.assetsLoading = false;
      this.assetsError = this.translate.instant('QUIZ.ERR_USERID_ASSETS');
      console.error(this.assetsError);
      return;
    }

    this.http
      .get<any>(apiUrl(`/api/user/${encodeURIComponent(this.userID)}/assets`))
      .subscribe({
        next: (data) => {
          this.assetsData = data || { devices: [], technological_assets: [] };
          this.devices = this.assetsData?.devices ?? [];
          this.techAssets = this.assetsData?.technological_assets ?? [];
          this.assetsLoading = false;
        },
        error: (err: HttpErrorResponse) => {
          console.error('Erreur chargement actifs', err);
          if (err.status === 404) {
            this.devices = [];
            this.techAssets = [];
            this.assetsError = this.translate.instant('QUIZ.ERR_NO_ASSETS_USER');
          } else {
            this.assetsError =
              err?.error?.error || this.translate.instant('QUIZ.ERR_ASSETS_GENERIC');
          }
          this.assetsLoading = false;
        }
      });
  }

  private loadRoleAssets(jobRole: string): void {
    this.http
      .get<any>(apiUrl(`/api/role_assets/${encodeURIComponent(jobRole)}`))
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
            .get<any[]>(apiUrl('/api/assets_catalog'), { params })
            .subscribe({
              next: (assets) => {
                this.assetsDetails = Array.isArray(assets) ? assets : [];
                const loc =
                  this.translate.currentLang === 'en'
                    ? 'en'
                    : this.translate.currentLang === 'es'
                      ? 'es'
                      : 'fr';
                this.assetsDetails.sort((a, b) =>
                  (a.name || '').localeCompare(b.name || '', loc)
                );
              },
              error: (err) => {
                console.error('Erreur /api/assets_catalog :', err);
                this.assetsDetails = [];
              }
            });
        },
        error: (err) => {
          console.error('Erreur /api/role_assets/:', err);
          this.roleAssets = [];
          this.assetsDetails = [];
        }
      });
  }

  // ================= PROFIL DE RISQUE =================

  private loadProfilRisque(): void {
    if (!this.userID) {
      console.error('userID manquant pour generate_profile_risk');
      return;
    }

    const payload = {
      userID: this.userID,
      profile: {
        jobRole: this.profile?.jobRole || '',
        qualifications: this.profile?.qualifications || [],
        keyResponsibilities: this.profile?.keyResponsibilities || []
      }
    };

    this.messageRisque = '';
    this.profilRisqueWarning = '';

    // 1) Cache Mongo (rapide), puis 2) régénération (évite course GET/POST)
    this.http
      .get<any>(apiUrl(`/api/profile_risk/${this.userID}`))
      .pipe(
        catchError(() => of(null)),
        switchMap((cached) => {
          if (cached) {
            this.profilRisque = cached;
            this.buildRiskDetailRows();
          }
          return this.http
            .post<any>(apiUrl('/generate_profile_risk'), payload)
            .pipe(timeout({ first: 15 * 60 * 1000 }));
        })
      )
      .subscribe({
        next: (res) => {
          console.log('🔍 /generate_profile_risk ->', res);
          this.profilRisque = res;
          this.messageRisque = res.message || '';
          this.profilRisqueWarning = '';
          this.buildRiskDetailRows();
        },
        error: (err: unknown) => {
          const http = err as HttpErrorResponse;
          const serverMsg =
            http?.error &&
            typeof http.error === 'object' &&
            http.error !== null &&
            'error' in http.error
              ? String((http.error as { error?: string }).error)
              : '';
          const timeoutMsg =
            err instanceof TimeoutError
              ? this.translate.instant('QUIZ.WARN_PROFILE_TIMEOUT')
              : '';
          const net =
            timeoutMsg ||
            (http.status === 0
              ? this.translate.instant('QUIZ.WARN_PROFILE_NET')
              : '');
          console.error('Erreur lors du chargement du profil de risque', err, {
            status: http?.status,
            serverMsg,
            net
          });

          if (this.profilRisque) {
            this.profilRisqueWarning =
              serverMsg ||
              net ||
              this.translate.instant('QUIZ.WARN_PROFILE_PARTIAL');
            return;
          }

          this.http.get<any>(apiUrl(`/api/profile_risk/${this.userID}`)).subscribe({
            next: (doc) => {
              this.profilRisque = doc;
              this.buildRiskDetailRows();
              this.profilRisqueWarning =
                serverMsg ||
                net ||
                this.translate.instant('QUIZ.WARN_PROFILE_REGEN');
            },
            error: () => {
              this.profilRisque = null;
              this.riskDetailRows = [];
              this.profilRisqueWarning =
                serverMsg ||
                net ||
                this.translate.instant('QUIZ.WARN_PROFILE_FAIL');
            }
          });
        }
      });
  }

  voirProfilRisque(): void {
    this.afficherProfilRisque = true;
    this.loadProfilRisque();
  }

  get riskItems() {
    if (!this.profilRisque) return [];
    const assets = this.profilRisque.assets || [];
    if (!Array.isArray(assets)) return [];

    const items: any[] = [];

    for (const a of assets) {
      const V = a.V ?? 0;
      const impact = a.impact ?? ((a.C || 0) + (a.I || 0) + (a.D || 0));
      const T = a.threat_score ?? a.T ?? 0;
      const risk_value_base = a.risk ?? (V * impact * T);

      const maxTheorique = 27;
      const risk_norm_pct =
        maxTheorique > 0
          ? Math.min(100, Math.round((risk_value_base / maxTheorique) * 100))
          : 0;

      let risk_level = this.translate.instant('QUIZ.RISK_LEVEL_LOW');
      if (risk_norm_pct >= 70) risk_level = this.translate.instant('QUIZ.RISK_LEVEL_HIGH');
      else if (risk_norm_pct >= 30) risk_level = this.translate.instant('QUIZ.RISK_LEVEL_MEDIUM');

      const human_techniques = a.human_techniques || a.exposed_techniques || [];

      const cia_asset: string[] = [];
      if (a.C > 0) cia_asset.push('C');
      if (a.I > 0) cia_asset.push('I');
      if (a.D > 0) cia_asset.push('D');

      if (human_techniques.length) {
        for (const ht of human_techniques) {
          const cia_t =
            Array.isArray(ht.cia_impact) && ht.cia_impact.length
              ? ht.cia_impact
              : cia_asset;

          const T_tech =
            Number(
              ht?.T ??
              ht?.threat_score ??
              a?.threat_score ??
              a?.T ??
              0
            ) || 0;

          items.push({
            technique_id: ht.technique_id || a.asset_id,
            technique_name: ht.technique_name || ht.description || a.asset_name,
            human_factor: true,
            asset_name: a.asset_name || a.asset_id,
            affects_assets: [a.asset_name || a.asset_id],
            access_types: [],
            human_techniques: [ht],
            V,
            I: impact,
            T: T_tech,
            risk_value: risk_value_base,
            risk_norm_pct,
            risk_level,
            cia_impact: cia_t,
            asset_cia_values: {
              C: a.C,
              I: a.I,
              D: a.D
            },
            comment: a.rationale || ''
          });
        }
      }
    }

    return items;
  }

  /**
   * Score de vulnérabilité affiché dans le tableau du profil.
   * Tant que le quiz pré n'est pas terminé (`preQuizCompleted` localStorage), on affiche 0.
   * Sinon on suit le profil API (`has_quiz_evaluation` + V).
   */
  displayVulnerabilityScore(r: { V?: number }): number {
    try {
      if (localStorage.getItem('preQuizCompleted') !== 'true') {
        return 0;
      }
    } catch {
      /* ignore */
    }
    const p = this.profilRisque;
    if (p?.has_quiz_evaluation === false) {
      return 0;
    }
    if (p?.has_quiz_evaluation === true) {
      return Number(r?.V ?? 0);
    }
    return Number(r?.V ?? 0);
  }

  // ================= TABLEAU RISQUE =================

  // trackBy doit inclure au minimum l'actif pour éviter de fusionner
  // plusieurs lignes qui partagent la même technique_id (ex: T1566 sur 4 actifs).
  trackRisk = (_: number, r: any) =>
    `${r?.technique_id ?? r?.technique_name ?? 'unknown'}__${r?.asset_name ?? r?.asset_id ?? 'asset'}`;

  riskClass(pct: number | undefined) {
    const v = pct ?? 0;
    if (v < 10) return 'low';
    if (v < 30) return 'medium';
    return 'high';
  }

  rowId(r: any): string {
    return r?.technique_id ?? r?.id ?? String(this.riskItems.indexOf(r));
  }

  private keyOf(r: any): string {
    return r?.technique_id || r?.id || JSON.stringify(r);
  }

  toggle(r: any) {
    const k = this.keyOf(r);
    this.opened = this.opened === k ? undefined : k;
  }

  isOpen(r: any) {
    return this.opened === this.keyOf(r);
  }

  closeDetails(r: any, ev: Event) {
    ev.stopPropagation();
    this.opened = undefined;
  }

  formatSummary(summary: string): string[] {
    if (!summary) return [];
    summary = summary
      .replace(/[()]/g, '')
      .replace(/:/g, ' : ')
      .replace(/\s+/g, ' ');
    return summary
      .split(/,|\sand\s|\bet\s/gi)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  // ================= QUIZ =================

  lancerQuizDepuisRisque(): void {
    this.afficherQuiz = true;
    this.genererQuiz();
  }

  genererQuiz(): void {
    this.quizGenerating = true;
    this.quizGenerateError = null;
    this.quizQuality = null;
    this.postQuizAlignment = null;
    // Ne plus afficher l'ancien quiz (pré/post) pendant le nouvel appel API
    this.questions = [];
    this.answers = [];
    this.isSubmitted = [];
    this.currentIndex = 0;
    this.submitted = false;
    this.result = null;
    this.training = '';
    this.quizFinished = false;

    const payload = {
      userID: this.userID,
      profile: this.profile,
      quiz_type: this.quizType,
      human_only: true,
      human_threats: this.humanThreatsFromProfile()
    };

    this.quizservice.generateQuiz(payload).subscribe({
      next: (res) => {
        this.quizGenerating = false;
        // Réponse Flask : { quiz_id, quiz: Question[], quality_metrics, ... }
        this.currentQuizId = res?.quiz_id ?? res?.quizId ?? this.currentQuizId;
        this.quizQuality = res?.quality_metrics ?? res?.qualityMetrics ?? null;
        this.postQuizAlignment = null;

        const raw = Array.isArray(res?.quiz) ? res.quiz : [];
        if (!raw.length) {
          console.error(
            '[Quiz] Réponse generate_quiz invalide ou sans tableau `quiz` :',
            res
          );
          this.quizGenerateError = this.translate.instant('QUIZ.ERR_QUIZ_EMPTY');
          return;
        }

        this.questions = raw.map((q: any) => ({
          ...q,
          choices: this.normalizeChoices(q?.choices ?? q?.options)
        }));
        this.answers = Array(this.questions.length).fill('');
        this.isSubmitted = Array(this.questions.length).fill(false);
        this.submitted = false;
        this.result = null;
        this.training = '';
        this.quizFinished = false;
        this.currentIndex = 0;
        this.riskDetailRows = [];
        localStorage.setItem('quizType', this.quizType);
        this.afficherQuiz = true;
        this.clearDraft(this.quizType);
        setTimeout(() => this.computePostQuizAlignment(), 0);
      },
      error: (err: HttpErrorResponse) => {
        this.quizGenerating = false;
        const msg =
          (err?.error &&
            typeof err.error === 'object' &&
            err.error !== null &&
            'error' in err.error &&
            String((err.error as { error?: string }).error)) ||
          err?.message ||
          this.translate.instant('QUIZ.ERR_QUIZ_NETWORK');
        this.quizGenerateError = msg;
        console.error('Erreur lors du lancement du quiz :', err);
      }
    });
  }

  submitQuestion(): void {
    this.isSubmitted[this.currentIndex] = true;
    this.saveDraft();
  }

  finishQuiz(): void {
    this.quizFinished = true;
    this.afficherFormationManuelle = false;
    this.submitted = true;

    const data = {
      answers: this.questions.map((q, i) => ({
        question: q.question,
        selected: this.answers[i] || ''
      })),
      total_questions: this.questions.length,
      userID: this.userID,
      quiz_type: this.quizType,
      profile: this.profile
    };

    console.log('Payload envoyé à /evaluate :', data);

    this.http.post<any>(apiUrl('/evaluate'), data).subscribe((res) => {
      if (res.answers?.length === this.questions.length) {
        this.questions = this.questions.map((q, i) => ({
          ...q,
          selected: res.answers[i].selected,
          correct_answer: res.answers[i].correct_answer,
          is_correct: res.answers[i].is_correct
        }));
      }

      if (this.quizType === 'pre') {
        localStorage.setItem('preQuizCompleted', 'true');
      }

      this.result = res;
      this.training = res.training || '';
      this.buildRiskDetailRows();

      const finalScore =
        res?.resultat?.user_score ??
        res?.user_score ??
        0;

      console.log('Score final :', finalScore);

      this.http
        .patch(
          apiUrl(`/api/users/${encodeURIComponent(this.userID)}/score`),
          { score: finalScore }
        )
        .subscribe({
          next: (updated) => console.log('Score mis à jour dans Mongo :', updated),
          error: (err) => console.error('Erreur maj score utilisateur', err)
        });

      this.http
        .post(apiUrl('/api/save_quiz_result'), {
          userID: this.userID,
          type: this.quizType,
          date: new Date().toISOString(),
          result: this.result,
          training: this.training
        })
        .subscribe({
          next: () => {
            console.log('Résultat enregistré');
            this.loadUserWithHistory();
            this.loadProfilRisque();
            this.clearDraft(this.quizType);
          },
          error: (err) => console.error('Erreur enregistrement quiz :', err)
        });

      if (!res.objectifAtteint && this.quizType === 'post') {
        this.generateTraining();
      }

      setTimeout(() => {
        const results = document.querySelector('.quiz-results');
        if (results) {
          (results as HTMLElement).scrollIntoView({ behavior: 'smooth' });
        }
      }, 200);
    });
  }

  buildRiskDetailRows(): void {
    // Si aucun résultat de quiz n'existe encore (profil de risque initial),
    // on force vulnérabilité = 0 pour toutes les techniques.
    if (!this.result) {
      this.riskDetailRows = this.riskItems.map((r: any) => {
        const triadValue = this.getAssetValue(r);
        const t = Number(r.T || 0);
        const vulnerability = 0;
        const localRisk = vulnerability * triadValue * t;

        return {
          technique_id: r.technique_id,
          technique_name: r.technique_name,
          triade: this.getTriadeLabel(r),
          vulnerability,
          triadValue,
          T: t,
          localRisk: Number(localRisk.toFixed(2)),
        };
      });

      console.log('riskDetailRows (profil initial) =', this.riskDetailRows);
      return;
    }

    // Après un quiz, on utilise la vulnérabilité réelle par technique
    const globalVuln = Number(this.result?.V_norm ?? 0);
    const perTechnique: any[] =
      this.result?.user_scores_per_technique ||
      this.result?.user_scores_per_thread ||
      [];

    const assetsRiskDetails = this.result?.assets_risk_details || [];

    this.riskDetailRows = this.riskItems.map((r: any) => {
      const triadValue = this.getAssetValue(r);
      const t = Number(r.T || 0);

      const techScore =
        perTechnique.find(
          (u: any) =>
            String(u.technique_id || '').toLowerCase() ===
            String(r.technique_id || '').toLowerCase()
        ) || null;

      const backendRow = assetsRiskDetails.find(
        (b: any) =>
            String(b?.technique_id || '').toLowerCase() ===
            String(r?.technique_id || '').toLowerCase()
      );
      const triadeConcernee = backendRow?.triade_concernee ?? this.getTriadeLabel(r);

      let vulnerability = globalVuln;
      if (techScore) {
        const vulnPct =
          Number(techScore.vulnerability_score ?? NaN) ||
          (typeof techScore.score_pct === 'number'
            ? 100 - Number(techScore.score_pct)
            : NaN);
        if (!Number.isNaN(vulnPct)) {
          vulnerability = vulnPct / 100;
        }
      }

      const localRisk = vulnerability * triadValue * t;

      return {
        technique_id: r.technique_id,
        technique_name: r.technique_name,
        triade: triadeConcernee,
        vulnerability,
        triadValue,
        T: t,
        localRisk: Number(localRisk.toFixed(2)),
      };
    });

    console.log('riskDetailRows (avec résultats) =', this.riskDetailRows);
  }

  generateTraining(): void {
    if (!this.userID) {
      console.error('userID manquant');
      return;
    }

    this.quizservice
      .generateTraining({
        userID: this.userID,
        profile: this.profile,
        quiz_type: this.quizType,
        results: this.result || undefined,
        human_threats: this.humanThreatsFromProfile(),
      })
      .subscribe({
        next: (res) => {
          console.log('Réponse generate_training =', res);

          const generatedTraining = res?.training || res?.content || '';

          if (!generatedTraining) {
            console.error('training manquant');
            return;
          }

          this.training = this.formatTraining(generatedTraining);
          localStorage.setItem('formation', JSON.stringify(generatedTraining));

          this.persistTrainingMeta({
            quality_metrics: res.quality_metrics,
            learning_summary: res.learning_summary,
          });

          const payload = {
            userID: this.userID,
            date: new Date().toISOString(),
            training: generatedTraining,
            objective: this.result?.objectifAtteint ?? false,
            quizType: this.quizType,
          };

          console.log('Payload savehistory_training =', payload);

          this.http
            .post(apiUrl('/api/savehistory_training'), payload)
            .subscribe({
              next: () => {
                console.log('Formation enregistrée dans MongoDB (dernier + historique)');
                this.loadUserWithHistory();
              },
              error: (err) =>
                console.error('Erreur enregistrement formation :', err),
            });

          alert(this.translate.instant('QUIZ.ALERT_TRAINING_SAVED'));
        },
        error: (err) => {
          console.error('Erreur lors de la génération de la formation :', err);
        },
      });
  }

  /** Charge métriques / résumé formation depuis localStorage (après reload). */
  private restoreTrainingMetaFromStorage(): void {
    try {
      const qm = localStorage.getItem('formation_quality_metrics');
      const ls = localStorage.getItem('formation_learning_summary');
      if (qm) {
        this.trainingQuality = JSON.parse(qm) as TrainingQualityMetrics;
      }
      if (ls) {
        this.trainingLearningSummary = JSON.parse(ls) as TrainingLearningSummary;
      }
    } catch {
      /* ignore */
    }
  }

  private persistTrainingMeta(meta: {
    quality_metrics?: TrainingQualityMetrics;
    learning_summary?: TrainingLearningSummary;
  }): void {
    if (meta.quality_metrics) {
      this.trainingQuality = meta.quality_metrics;
      localStorage.setItem(
        'formation_quality_metrics',
        JSON.stringify(meta.quality_metrics)
      );
    }
    if (meta.learning_summary) {
      this.trainingLearningSummary = meta.learning_summary;
      localStorage.setItem(
        'formation_learning_summary',
        JSON.stringify(meta.learning_summary)
      );
    }
  }

  /**
   * Vérifie que les technique_id du quiz post recoupent ceux enseignés dans la dernière formation.
   */
  computePostQuizAlignment(): void {
    this.postQuizAlignment = null;
    if (this.quizType !== 'post' || !this.questions?.length) {
      return;
    }

    let techniques = this.trainingLearningSummary?.techniques || [];
    if (!techniques.length) {
      try {
        const raw = localStorage.getItem('formation_learning_summary');
        if (raw) {
          const ls = JSON.parse(raw) as TrainingLearningSummary;
          techniques = ls.techniques || [];
        }
      } catch {
        /* ignore */
      }
    }

    const formIds = [
      ...new Set(
        techniques
          .map((t) => (t.technique_id || '').toString().toUpperCase())
          .filter(Boolean)
      ),
    ];

    const qids = [
      ...new Set(
        this.questions
          .map((q) =>
            (q.technique_id || q.techniqueId || '').toString().toUpperCase()
          )
          .filter(Boolean)
      ),
    ];

    const noFormationData = formIds.length === 0;
    const setF = new Set(formIds);
    const setQ = new Set(qids);
    const missingInQuiz = [...setF].filter((x) => !setQ.has(x));
    const extraInQuiz = [...setQ].filter((x) => !setF.has(x));

    this.postQuizAlignment = {
      formationTechniques: formIds,
      quizTechniques: qids,
      missingInQuiz,
      extraInQuiz,
      /** Toutes les techniques de la formation sont couvertes par au moins une question post. */
      aligned: !noFormationData && missingInQuiz.length === 0,
      noFormationData,
    };
  }

  updateAnswer(index: number, value: string): void {
    this.answers[index] = value;
    this.saveDraft();
  }

  private normalizeChoices(raw: any): string[] {
    if (!raw) return [];

    if (Array.isArray(raw)) {
      return raw
        .map((opt) => this.choiceValue(opt))
        .filter((s) => !!s);
    }

    if (typeof raw === 'object') {
      return Object.values(raw)
        .map((v) => this.choiceValue(v))
        .filter((s) => !!s);
    }

    return [String(raw)];
  }

  getTechniqueLabel(q: any): string | null {
    if (!q) return null;
    const name = q.technique_name || q.techniqueName;
    const tid = q.technique_id || q.techniqueId || q.threadId;
    if (name && tid) return `${tid} — ${name}`;
    if (name) return name;
    if (tid) return String(tid);
    return null;
  }

  choiceValue(opt: any): string {
    if (opt === null || opt === undefined) return '';
    if (typeof opt === 'string') return opt.trim();
    if (typeof opt === 'object') {
      return (
        (opt.value ?? opt.text ?? opt.label ?? opt.option ?? opt.choice ?? '').toString().trim()
      );
    }
    return String(opt).trim();
  }

  private humanThreatsFromProfile(): any[] {
    const threats: any[] = [];
    const assets = this.profilRisque?.assets;
    if (!Array.isArray(assets)) return threats;

    for (const a of assets) {
      const ht = a?.human_techniques;
      if (!ht) continue;
      const list = Array.isArray(ht) ? ht : [ht];
      for (const t of list) {
        if (!t) continue;
        const tid = t.technique_id || t.id;
        threats.push({
          technique_id: tid,
          technique_name: t.technique_name || t.description || tid,
          description: t.description,
          asset_name: a.asset_name || a.asset_id,
          threat_score: t.threat_score ?? a.threat_score ?? a.T
        });
      }
    }
    return threats;
  }

  private isMitreId(val: any): boolean {
    if (!val) return false;
    const s = String(val).trim().toUpperCase();
    return /^T\d{4,5}(?:\.\d{3})?$/.test(s);
  }

  onTextInput(event: Event, index: number): void {
    const input = event.target as HTMLInputElement;
    this.updateAnswer(index, input.value);
  }

  startPostQuiz(): void {
    this.quizType = 'post';
    this.submitted = false;
    this.answers = [];
    this.isSubmitted = [];
    this.result = null;
    this.training = '';
    this.riskDetailRows = [];

    this.quizFinished = false;
    this.afficherQuiz = true;
    this.afficherFormationManuelle = false;
    this.afficherProfilRisque = false;

    localStorage.setItem('quizType', 'post');
    this.genererQuiz();

    setTimeout(() => {
      const form = document.querySelector('form');
      if (form) {
        (form as HTMLElement).scrollIntoView({ behavior: 'smooth' });
      }
    }, 200);
  }

  isCorrect(index: number): boolean {
    const user = this.answers[index]?.trim().toLowerCase();
    const correct = this.questions[index]?.correct_answer?.trim().toLowerCase();
    return user === correct;
  }

  /** True si l'utilisateur a choisi au moins une réponse pour la question à l'index donné. */
  hasSelectedAnswer(index: number): boolean {
    const a = this.answers[index];
    return typeof a === 'string' && a.trim().length > 0;
  }

  prevQuestion(): void {
    if (this.currentIndex > 0) this.currentIndex--;
    this.saveDraft();
  }

  nextQuestion(): void {
    if (this.currentIndex < this.questions.length - 1) this.currentIndex++;
    this.saveDraft();
  }

  normalize(text: string): string {
    return text?.toString().trim().toLowerCase();
  }

  // ================= EXPORTS / FORMATTING =================

  downloadTrainingAsPDF(): void {
    const section = document.querySelector('.training-section');
    if (!section) return;

    const clone = section.cloneNode(true) as HTMLElement;
    const actions = clone.querySelector('.training-actions');
    if (actions) actions.remove();
    clone.setAttribute('id', 'pdf-clone-temp');
    clone.style.cssText = 'position: absolute; left: -9999px; top: 0; width: 210mm; max-width: 800px; padding: 20px; background: #fff; color: #333;';
    document.body.appendChild(clone);

    const opt = {
      margin: 0.5,
      filename: `formation_cybersecurite_${new Date().toISOString().slice(0, 10)}.pdf`,
      image: { type: 'jpeg', quality: 0.98 },
      html2canvas: { scale: 2, useCORS: true, logging: false },
      jsPDF: { unit: 'in', format: 'a4', orientation: 'portrait' }
    };

    const cleanup = () => {
      if (clone.parentNode) clone.parentNode.removeChild(clone);
    };

    html2pdf()
      .set(opt)
      .from(clone)
      .save()
      .then(cleanup)
      .catch(() => cleanup());
  }

  printTraining(): void {
    const content = document.getElementById('trainingContent');
    if (!content) return;

    const isHTML = /<\/?[a-z][\s\S]*>/i.test(content.innerHTML.trim());
    const printableContent = isHTML
      ? content.innerHTML
      : this.formatTraining(content.innerText);

    const win = window.open('', '', 'width=800,height=600');
    if (win) {
      win.document.open();
      win.document.write(`
        <html>
          <head>
            <title>Formation</title>
            <style>
              body { font-family: Arial, sans-serif; padding: 20px; color: #333; }
              h2 { font-size: 22px; text-align: center; color: #003366; margin-top: 10px; }
              p { margin: 10px 0; }
              ul, ol { margin: 10px 0 10px 20px; }
              li { margin: 5px 0; }
              .logo { max-width: 100px; display: block; margin-bottom: 10px; }
              .date { text-align: right; font-size: 0.9rem; color: #555; margin-bottom: 20px; }
              .footer { border-top: 1px solid #ccc; margin-top: 40px; padding-top: 10px; font-size: 0.8rem; color: #888; text-align: center; }
            </style>
          </head>
          <body>
            <img src="${location.origin}/assets/images/cyberform.png" class="logo" alt="Logo CyberForm" />
            <h2>Formation en Cybersécurité</h2>
            <p class="date">Date : ${new Date().toLocaleDateString('fr-CA')}</p>
            ${printableContent}
            <div class="footer">
              CyberForm – Formation confidentielle à usage interne.<br>
              Contact : support@cyberform.com
            </div>
          </body>
        </html>
      `);
      win.document.close();
      win.focus();
      setTimeout(() => win.print(), 500);
    }
  }

  formatTraining(raw: string): string {
    if (!raw) return '';
    let formatted = raw.trim();
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    if (/- .+/g.test(formatted)) {
      formatted = formatted.replace(
        /(?:^- .+\n?)+/gm,
        (match) => {
          const items = match
            .trim()
            .split('\n')
            .map((item) => `<li>${item.slice(2)}</li>`)
            .join('');
          return `<ul>${items}</ul>`;
        }
      );
    }

    if (/^\d+\. .+/gm.test(formatted)) {
      formatted = formatted.replace(
        /(?:^\d+\. .+\n?)+/gm,
        (match) => {
          const items = match
            .trim()
            .split('\n')
            .map((item) => {
              const text = item.replace(/^\d+\.\s/, '');
              return `<li>${text}</li>`;
            })
            .join('');
          return `<ol>${items}</ol>`;
        }
      );
    }

    formatted = formatted.replace(/(?:\r\n|\r|\n){2,}/g, '</p><p>');
    formatted = `<p>${formatted}</p>`;
    return formatted;
  }

  voirFormation(): void {
    if (!this.training) {
      this.generateTraining();
    }
    this.afficherFormationManuelle = true;
  }

  hasC(r: any): boolean {
    return Array.isArray(r?.cia_impact) && r.cia_impact.includes('C');
  }

  hasI(r: any): boolean {
    return Array.isArray(r?.cia_impact) && r.cia_impact.includes('I');
  }

  hasD(r: any): boolean {
    return Array.isArray(r?.cia_impact) && r.cia_impact.includes('D');
  }

  /** Option 2 : triade au niveau de la technique (cia_impact). Sinon repli sur l'actif (C, I, D). */
  getTriadeLabel(r: any): string {
    const parts: string[] = [];
    const cia = Array.isArray(r?.cia_impact) ? r.cia_impact : [];

    if (cia.length) {
      if (cia.includes('C')) parts.push(this.translate.instant('USER.PROFILE.CONFIDENTIALITY'));
      if (cia.includes('I')) parts.push(this.translate.instant('USER.PROFILE.INTEGRITY'));
      if (cia.includes('D')) parts.push(this.translate.instant('USER.PROFILE.AVAILABILITY'));
    } else {
      const v = r?.asset_cia_values || {};
      if (v.C !== undefined && v.C > 0) {
        parts.push(this.translate.instant('USER.PROFILE.CONFIDENTIALITY'));
      }
      if (v.I !== undefined && v.I > 0) {
        parts.push(this.translate.instant('USER.PROFILE.INTEGRITY'));
      }
      if (v.D !== undefined && v.D > 0) {
        parts.push(this.translate.instant('USER.PROFILE.AVAILABILITY'));
      }
    }

    return parts.length ? parts.join(', ') : this.translate.instant('QUIZ.TRIADE_UNSPECIFIED');
  }

  getAssetValueLabel(r: any): string {
    const v = r?.asset_cia_values || {};
    const cia = Array.isArray(r?.cia_impact) ? r.cia_impact : [];
    const parts: string[] = [];

    if (cia.includes('C') && v.C !== undefined) {
      parts.push(
        this.translate.instant('QUIZ.TRIADE_VAL', {
          label: this.translate.instant('USER.PROFILE.CONFIDENTIALITY'),
          v: v.C
        })
      );
    }
    if (cia.includes('I') && v.I !== undefined) {
      parts.push(
        this.translate.instant('QUIZ.TRIADE_VAL', {
          label: this.translate.instant('USER.PROFILE.INTEGRITY'),
          v: v.I
        })
      );
    }
    if (cia.includes('D') && v.D !== undefined) {
      parts.push(
        this.translate.instant('QUIZ.TRIADE_VAL', {
          label: this.translate.instant('USER.PROFILE.AVAILABILITY'),
          v: v.D
        })
      );
    }

    return parts.length ? parts.join(' / ') : '-';
  }

  get scoreUser(): number {
    return Number(this.result?.user_score ?? 0);
  }

  get scoreTotal(): number {
    return Number(this.result?.total_questions ?? 0);
  }

  get vulnerabilityPct(): number {
    return Number(this.result?.vulnerability_score ?? 0);
  }

  get impactTotal(): number {
    return Number(this.result?.impact_total ?? 0);
  }

  get vNorm(): number {
    return Number(this.result?.V_norm ?? 0);
  }

  get riskBrut(): number {
    return Number(this.result?.risk_brut ?? 0);
  }

  get riskNormalized(): number {
    return Number(this.result?.risk_norm_pct ?? 0);
  }

  sanitizeFeedback(feedback: string): string {
    return feedback
      .replace(/\n/g, '<br>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  }

  getAssetValue(r: any): number {
    const cia = r?.asset_cia_values || {};
    const impacts: string[] = r?.cia_impact || [];

    let value = 0;
    if (impacts.includes('C')) value += cia.C || 0;
    if (impacts.includes('I')) value += cia.I || 0;
    if (impacts.includes('D')) value += cia.D || 0;

    return value;
  }

  getGlobalRisk(): number {
    if (!this.riskDetailRows || this.riskDetailRows.length === 0) {
      return 0;
    }

    const total = this.riskDetailRows.reduce((sum, r) => sum + (r.localRisk || 0), 0);
    return Number(total.toFixed(2));
  }

  /** Retourne user_scores_per_thread (ou user_scores_per_technique) pour affichage dans les résultats. */
  getScoresPerThread(): any[] {
    const r = this.result;
    if (!r) return [];
    const list = r.user_scores_per_technique ?? r.user_scores_per_thread;
    return Array.isArray(list) ? list : [];
  }

  getRiskClass(value: number | null | undefined): string {
  const risk = Number(value ?? 0);

  if (risk >= 60) {
    return 'risk-critical';
  }

  if (risk >= 40) {
    return 'risk-high';
  }

  if (risk >= 20) {
    return 'risk-medium';
  }

  return 'risk-low';
}
get learnedThresholdPct(): number {
  return Number(this.result?.learned_threshold_pct ?? 0);
}

get policyThresholdPct(): number {
  return Number(this.result?.policy_threshold_pct ?? 0);
}

get finalThresholdPct(): number {
  return Number(this.result?.final_threshold_pct ?? 0);
}
getComparisonSymbol(
  currentValue: number | null | undefined,
  thresholdValue: number | null | undefined
): string {
  const current = Number(currentValue ?? 0);
  const threshold = Number(thresholdValue ?? 0);

  if (current < threshold) return '<';
  if (current > threshold) return '>';
  return '=';
}

getComparisonMessage(
  currentValue: number | null | undefined,
  thresholdValue: number | null | undefined
): string {
  const current = Number(currentValue ?? 0);
  const threshold = Number(thresholdValue ?? 0);

  if (current < threshold) {
    return this.translate.instant('QUIZ.CMP_RISK_BELOW');
  }

  if (current > threshold) {
    return this.translate.instant('QUIZ.CMP_RISK_ABOVE');
  }

  return this.translate.instant('QUIZ.CMP_RISK_EQUAL');
}
}