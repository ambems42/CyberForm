import { Component, ElementRef, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';
import { Subscription, forkJoin, of } from 'rxjs';
import { catchError, finalize, tap } from 'rxjs/operators';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { AuthService } from '../auth.service';
import { QuizService, QuizQualityMetricItem } from '../quiz.service';
import { apiUrl } from '../api-url';
import {
  ApexChart,
  ApexPlotOptions,
  ApexFill,
  ApexStroke,
  ApexNonAxisChartSeries,
  ApexAxisChartSeries,
  ApexXAxis,
  ApexDataLabels
} from 'ng-apexcharts';

export type RadialChartOptions = {
  series: ApexNonAxisChartSeries;
  chart: ApexChart;
  plotOptions: ApexPlotOptions;
  fill: ApexFill;
  stroke: ApexStroke;
  labels: string[];
};

export type BarChartOptions = {
  series: ApexAxisChartSeries;
  chart: ApexChart;
  plotOptions: ApexPlotOptions;
  dataLabels: ApexDataLabels;
  xaxis: ApexXAxis;
};

export type AdminRadialLabelKey = 'riskGlobal' | 'usersRisk' | 'objectives' | 'trainings';

export type MitreCatalogRow = {
  id: string;
  name: string;
  thresholdPct: number | null;
};

@Component({
  selector: 'app-admin',
  templateUrl: './admin.component.html',
  styleUrls: ['./admin.component.css']
})
export class AdminComponent implements OnInit, OnDestroy {
  @ViewChild('orgSaveFeedback') orgSaveFeedback?: ElementRef<HTMLElement>;

  users: any[] = [];
  stats: any = {};
  seuilRisque = 30;
  prenom: string = '';
  searchTerm: string = '';
  showCreateUser = false;
  score = 0;
  activeSection: string = 'dashboard';
  filterMode: 'all' | 'risk' | 'noPost' | 'lateTraining' | 'badProfile' = 'all';

  selectedUser: any = null;
  selectedUserQuiz: any[] = [];
  selectedUserFormation: any = null;
  quizPre: any[] = [];
  quizPost: any[] = [];
  selectedUserID: string | null = null;

  /** Métriques qualité quiz (API /api/quiz_quality_metrics) */
  quizQualityItems: QuizQualityMetricItem[] = [];
  quizQualityLoading = false;
  quizQualityError: string | null = null;
  qualityFilterUserId = '';
  qualityLimit = 100;

  /** Paramètres organisation (/api/admin/organization_settings) */
  orgSettingsLoading = false;
  orgSettingsSaving = false;
  orgSettingsError: string | null = null;
  orgSettingsSaved = false;
  policyThresholdPct = 30;
  kThreshold = 0.95;
  learnedHistoryWindow = 10;
  learnedMinPct = 15;
  learnedMaxPct = 45;
  criticalVulnThresholdPct = 50;
  criticalTechniqueMode: 'default' | 'custom' | 'disabled' = 'default';
  criticalTechniqueIdsText = '';

  /** Catalogue MITRE (m.py) + seuil optionnel par ligne */
  mitreCatalogRows: MitreCatalogRow[] = [];
  mitreCatalogFilter = '';
  /** IDs hors catalogue (saisie libre) */
  customPerTechniqueRows: { techniqueId: string; thresholdPct: number }[] = [];

  private langSub?: Subscription;

  private readonly radialLabelKeys: Record<AdminRadialLabelKey, string> = {
    riskGlobal: 'ADMIN.CHART_RISK_GLOBAL',
    usersRisk: 'ADMIN.CHART_USERS_AT_RISK',
    objectives: 'ADMIN.CHART_OBJECTIVES',
    trainings: 'ADMIN.CHART_TRAININGS'
  };

  scoreRisque = 0;
  scoreObjectifs = 0;
  scoreFormations = 0;

  chartOptions: RadialChartOptions = {
    series: [0],
    chart: {
      height: 250,
      type: 'radialBar',
      zoom: { enabled: false },
      toolbar: { show: false }
    },
    plotOptions: {
      radialBar: {
        hollow: { size: '70%' },
        dataLabels: {
          name: { show: true, fontSize: '18px' },
          value: { show: true, fontSize: '20px', fontWeight: 600, color: '#28a745' }
        }
      }
    },
    fill: { type: 'solid', colors: ['#28a745'] },
    stroke: { lineCap: 'round' },
    labels: ['Risque global']
  };

  chartRisque: RadialChartOptions = {
    series: [0],
    chart: {
      height: 250,
      type: 'radialBar',
      zoom: { enabled: false },
      toolbar: { show: false }
    },
    plotOptions: {
      radialBar: {
        hollow: { size: '70%' },
        dataLabels: {
          name: { show: true, fontSize: '16px' },
          value: { show: true, fontSize: '20px', fontWeight: 600, color: '#fd7e14' }
        }
      }
    },
    fill: { type: 'solid', colors: ['#fd7e14'] },
    stroke: { lineCap: 'round' },
    labels: ['Utilisateurs à risque']
  };

  chartObjectifs: RadialChartOptions = {
    series: [0],
    chart: {
      height: 250,
      type: 'radialBar',
      zoom: { enabled: false },
      toolbar: { show: false }
    },
    plotOptions: {
      radialBar: {
        hollow: { size: '70%' },
        dataLabels: {
          name: { show: true, fontSize: '16px' },
          value: { show: true, fontSize: '20px', fontWeight: 600, color: '#28a745' }
        }
      }
    },
    fill: { type: 'solid', colors: ['#28a745'] },
    stroke: { lineCap: 'round' },
    labels: ['Objectifs atteints']
  };

  chartFormations: RadialChartOptions = {
    series: [0],
    chart: {
      height: 250,
      type: 'radialBar',
      zoom: { enabled: false },
      toolbar: { show: false }
    },
    plotOptions: {
      radialBar: {
        hollow: { size: '70%' },
        dataLabels: {
          name: { show: true, fontSize: '16px' },
          value: { show: true, fontSize: '20px', fontWeight: 600, color: '#0ea5e9' }
        }
      }
    },
    fill: { type: 'solid', colors: ['#0ea5e9'] },
    stroke: { lineCap: 'round' },
    labels: ['Formations planifiées']
  };

  barChartOptions: BarChartOptions = {
    series: [{ name: 'Score utilisateur', data: [] }],
    chart: { type: 'bar', height: 350 },
    plotOptions: {
      bar: { horizontal: false, columnWidth: '55%' }
    },
    dataLabels: { enabled: false },
    xaxis: { categories: [] }
  };

  constructor(
    private http: HttpClient,
    private router: Router,
    private quizService: QuizService,
    private auth: AuthService,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {
    this.prenom = this.auth.getCurrentUser()?.prenom || '';
    this.orgSettingsLoading = true;
    forkJoin({
      catalog: this.http
        .get<{ items: { id: string; name: string }[] }>(apiUrl('/api/admin/mitre_techniques_catalog'))
        .pipe(catchError(() => of({ items: [] as { id: string; name: string }[] }))),
      org: this.http.get<Record<string, unknown>>(apiUrl('/api/admin/organization_settings'))
    })
      .pipe(
        tap(({ catalog, org }) => {
          this.mitreCatalogRows = (catalog.items || []).map((i) => ({
            id: i.id,
            name: i.name,
            thresholdPct: null
          }));
          this.applyOrganizationSettingsFromApi(org);
        }),
        finalize(() => {
          this.orgSettingsLoading = false;
          this.loadUsers();
          this.loadStats();
        })
      )
      .subscribe({ error: () => {} });
    this.langSub = this.translate.onLangChange.subscribe(() => {
      this.loadUsers();
      this.loadStats();
    });
  }

  ngOnDestroy(): void {
    this.langSub?.unsubscribe();
  }

  private localeForChart(): string {
    const lang = this.translate.currentLang || 'fr';
    if (lang === 'en') return 'en-US';
    if (lang === 'es') return 'es-ES';
    return 'fr-FR';
  }

  private toNumberStrict(v: any): number | null {
    if (v === null || v === undefined) return null;
    const s = String(v).trim();
    if (s === '') return null;
    const n = Number(s.replace(',', '.'));
    return Number.isFinite(n) ? n : null;
  }

  private applyOrganizationSettingsFromApi(s: Record<string, unknown>): void {
    if (!s || typeof s !== 'object') return;
    this.policyThresholdPct = Number(s['policy_threshold_pct'] ?? 30);
    this.seuilRisque = this.policyThresholdPct;
    this.kThreshold = Number(s['k_threshold'] ?? 0.95);
    this.learnedHistoryWindow = Number(s['learned_history_window'] ?? 10);
    this.learnedMinPct = Number(s['learned_min_pct'] ?? 15);
    this.learnedMaxPct = Number(s['learned_max_pct'] ?? 45);
    this.criticalVulnThresholdPct = Number(s['critical_vulnerability_threshold_pct'] ?? 50);
    const crit = s['critical_technique_ids'];
    if (crit === null || crit === undefined) {
      this.criticalTechniqueMode = 'default';
      this.criticalTechniqueIdsText = '';
    } else if (Array.isArray(crit) && crit.length === 0) {
      this.criticalTechniqueMode = 'disabled';
      this.criticalTechniqueIdsText = '';
    } else if (Array.isArray(crit)) {
      this.criticalTechniqueMode = 'custom';
      this.criticalTechniqueIdsText = crit.map(String).join('\n');
    } else {
      this.criticalTechniqueMode = 'default';
      this.criticalTechniqueIdsText = '';
    }
    this.mergePerTechniqueThresholdsMap(s['per_technique_vulnerability_thresholds']);
  }

  /** Lignes catalogue filtrées (recherche ID ou nom) */
  get filteredMitreCatalogRows(): MitreCatalogRow[] {
    const q = this.mitreCatalogFilter.trim().toLowerCase();
    if (!q) return this.mitreCatalogRows;
    return this.mitreCatalogRows.filter(
      (r) =>
        r.id.toLowerCase().includes(q) ||
        (r.name && r.name.toLowerCase().includes(q))
    );
  }

  private mergePerTechniqueThresholdsMap(obj: unknown): void {
    if (!this.mitreCatalogRows.length) {
      this.applyLegacyPerTechniqueOnlyToCustom(obj);
      return;
    }
    const saved = obj && typeof obj === 'object' ? (obj as Record<string, unknown>) : {};
    const catalogIds = new Set(this.mitreCatalogRows.map((r) => r.id.toUpperCase()));
    for (const row of this.mitreCatalogRows) {
      const key = row.id.toUpperCase();
      const raw = saved[key];
      const n = raw !== undefined ? Number(raw) : NaN;
      row.thresholdPct = Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : null;
    }
    const custom: { techniqueId: string; thresholdPct: number }[] = [];
    for (const [k, v] of Object.entries(saved)) {
      const ku = String(k).trim().toUpperCase();
      if (!ku || catalogIds.has(ku)) continue;
      const n = Number(v);
      if (!Number.isFinite(n)) continue;
      custom.push({ techniqueId: ku, thresholdPct: Math.max(0, Math.min(100, n)) });
    }
    custom.sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));
    this.customPerTechniqueRows = custom;
  }

  private applyLegacyPerTechniqueOnlyToCustom(obj: unknown): void {
    if (!obj || typeof obj !== 'object') {
      this.customPerTechniqueRows = [];
      return;
    }
    const o = obj as Record<string, unknown>;
    const rows: { techniqueId: string; thresholdPct: number }[] = [];
    for (const [k, v] of Object.entries(o)) {
      const tid = String(k).trim();
      if (!tid) continue;
      const n = Number(v);
      if (!Number.isFinite(n)) continue;
      rows.push({ techniqueId: tid.toUpperCase(), thresholdPct: Math.max(0, Math.min(100, n)) });
    }
    rows.sort((a, b) => a.techniqueId.localeCompare(b.techniqueId));
    this.customPerTechniqueRows = rows;
  }

  private buildPerTechniqueThresholdsPayload(): Record<string, number> {
    const out: Record<string, number> = {};
    for (const row of this.mitreCatalogRows) {
      if (row.thresholdPct == null || Number.isNaN(Number(row.thresholdPct))) continue;
      const n = Number(row.thresholdPct);
      if (!Number.isFinite(n)) continue;
      out[row.id.toUpperCase()] = Math.max(0, Math.min(100, n));
    }
    for (const row of this.customPerTechniqueRows) {
      const tid = row.techniqueId.trim();
      if (!tid) continue;
      const n = Number(row.thresholdPct);
      if (!Number.isFinite(n)) continue;
      out[tid.toUpperCase()] = Math.max(0, Math.min(100, n));
    }
    return out;
  }

  addCustomPerTechniqueRow(): void {
    this.customPerTechniqueRows.push({ techniqueId: '', thresholdPct: 50 });
  }

  removeCustomPerTechniqueRow(index: number): void {
    this.customPerTechniqueRows.splice(index, 1);
  }

  saveOrganizationSettings(): void {
    this.orgSettingsSaving = true;
    this.orgSettingsError = null;
    this.orgSettingsSaved = false;
    let critical_technique_ids: string[] | null;
    if (this.criticalTechniqueMode === 'default') {
      critical_technique_ids = null;
    } else if (this.criticalTechniqueMode === 'disabled') {
      critical_technique_ids = [];
    } else {
      critical_technique_ids = this.criticalTechniqueIdsText
        .split(/[\n,]+/)
        .map((x) => x.trim())
        .filter(Boolean);
    }
    const body = {
      policy_threshold_pct: Number(this.policyThresholdPct),
      k_threshold: Number(this.kThreshold),
      learned_history_window: Math.round(Number(this.learnedHistoryWindow)),
      learned_min_pct: Number(this.learnedMinPct),
      learned_max_pct: Number(this.learnedMaxPct),
      critical_vulnerability_threshold_pct: Number(this.criticalVulnThresholdPct),
      critical_technique_ids,
      per_technique_vulnerability_thresholds: this.buildPerTechniqueThresholdsPayload()
    };
    this.http
      .post<any>(apiUrl('/api/admin/organization_settings'), body)
      .pipe(finalize(() => (this.orgSettingsSaving = false)))
      .subscribe({
        next: (s) => {
          this.applyOrganizationSettingsFromApi(s);
          this.orgSettingsSaved = true;
          this.loadUsers();
          this.loadStats();
          this.scrollOrgSaveFeedbackIntoView();
        },
        error: (err) => {
          this.orgSettingsError =
            err?.error?.error ||
            this.translate.instant('ADMIN.ORG_SETTINGS_SAVE_ERROR');
          this.scrollOrgSaveFeedbackIntoView();
        }
      });
  }

  /** Affiche le message succès/erreur près du bouton sans devoir remonter la page. */
  private scrollOrgSaveFeedbackIntoView(): void {
    setTimeout(() => {
      const el = this.orgSaveFeedback?.nativeElement;
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    }, 0);
  }

  loadUsers(): void {
    const getDate = (d: any): Date | null => {
      if (!d) return null;
      if (typeof d === 'string') return new Date(d);
      if (typeof d === 'object' && '$date' in d) return new Date(d.$date);
      return null;
    };

    const getStatut = (nextEval: Date | null): { label: string; color: string } => {
      if (!nextEval) {
        return { label: this.translate.instant('ADMIN.STATUS_NOT_DEFINED'), color: 'badge-grey' };
      }
      const today = new Date();
      const diff = (nextEval.getTime() - today.getTime()) / (1000 * 60 * 60 * 24);
      if (diff < 0) return { label: this.translate.instant('ADMIN.STATUS_LATE'), color: 'badge-red' };
      if (diff <= 3) {
        return { label: this.translate.instant('ADMIN.STATUS_FOLLOW_SOON'), color: 'badge-orange' };
      }
      return { label: this.translate.instant('ADMIN.STATUS_OK'), color: 'badge-green' };
    };

    const FR_MONTHS: Record<string, number> = {
      janvier: 0, fevrier: 1, 'février': 1, mars: 2, avril: 3, mai: 4, juin: 5,
      juillet: 6, aout: 7, 'août': 7, septembre: 8, octobre: 9, novembre: 10,
      decembre: 11, 'décembre': 11
    };

    function parseFrDateString(v: unknown): Date | null {
      if (!v) return null;
      if (v instanceof Date && !isNaN(v.getTime())) return v;

      const s = String(v).trim().toLowerCase().replace(/\s+/g, ' ');
      const m = s.match(/^(\d{1,2})\s+([a-zéûîôàù]+)\s+(\d{4})(?:\s*(?:à|a)\s*(\d{1,2})(?::(\d{2}))?)?$/i);
      if (!m) return null;

      const day = +m[1];
      const monthKey = m[2]
        .replace('fé', 'fe').replace(/é/g, 'e')
        .replace('ô', 'o').replace('î', 'i').replace('û', 'u')
        .replace('à', 'a').replace('ù', 'u')
        .replace('ï', 'i').replace('ö', 'o').replace('ç', 'c');
      const month = FR_MONTHS[monthKey] ?? FR_MONTHS[m[2]];
      const year = +m[3];
      const hh = m[4] ? +m[4] : 0;
      const mm = m[5] ? +m[5] : 0;

      if (month == null) return null;
      const d = new Date(year, month, day, hh, mm, 0, 0);
      return isNaN(d.getTime()) ? null : d;
    }

    this.http.get<any[]>(apiUrl('/api/users')).subscribe({
      next: data => {
        this.users = (data || []).map((u: any) => {
          const lastEval = parseFrDateString(u.lastEvaluationDate) || getDate(u.lastEvaluationDate);
          const nextEval = parseFrDateString(u.nextEvaluationDate) || getDate(u.nextEvaluationDate);
          const lastTrain = parseFrDateString(u.lastTrainingDate) || getDate(u.lastTrainingDate);
          const nextTrain = parseFrDateString(u.nextTrainingDate) || getDate(u.nextTrainingDate);

          const statut = getStatut(nextEval);
          const resultatOrig = (Array.isArray(u.resultat) ? u.resultat[0] : u.resultat) || {};
          const userScore = this.toNumberStrict(resultatOrig.user_score ?? u.user_score);
          const resultat = { ...resultatOrig, user_score: userScore };

const riskNormPct = this.toNumberStrict(u.riskNormPct ?? u.risk_score);

const lastPostQuiz = (Array.isArray(u.quiz_history) ? u.quiz_history : [])
  .filter((q: any) => q.quiz_type === 'post')
  .sort((a: any, b: any) => new Date(b.date).getTime() - new Date(a.date).getTime())[0];

const postQuizManquant = !lastPostQuiz && (riskNormPct ?? 0) >= this.seuilRisque;

const formationEnRetard = (() => {
  const nextTrainDate = nextTrain;
  if (!nextTrainDate) return false;
  const today = new Date();
  return nextTrainDate.getTime() < today.getTime();
})();

return {
  ...u,
  resultat,
  riskNormPct,
  showDetails: false,
  // Aligné backend / dernier quiz : objectif = résultat du test, pas « risque < 30 % » seul
  objectifAtteint: !!u.objectifAtteint,
  profile_acceptable: u.profile_acceptable,
  profile_quality_score: u.profile_quality_score,
  lastEvaluationDate: lastEval,
  nextEvaluationDate: nextEval,
  lastTrainingDate: lastTrain,
  nextTrainingDate: nextTrain,
  statutLabel: statut.label,
  statutColor: statut.color,
  postQuizManquant,
  formationEnRetard
};
       
        }).sort((a, b) => (b.riskNormPct ?? 0) - (a.riskNormPct ?? 0));

        const utilisateurs = this.users.filter(u => u.basic_info?.role !== 'admin');
        const locale = this.localeForChart();
        this.barChartOptions.series = [{
          name: this.translate.instant('ADMIN.BAR_SCORE_SERIES'),
          data: utilisateurs.map(u => Number(u.resultat?.user_score ?? 0))
        }];
        this.barChartOptions.xaxis = {
          categories: utilisateurs.map(u => {
            const date = u.lastEvaluationDate
              ? new Date(u.lastEvaluationDate).toLocaleDateString(locale, {
                  year: 'numeric',
                  month: 'short',
                  day: '2-digit'
                })
              : this.translate.instant('COMMON.NOT_AVAILABLE');
            return `${u.basic_info?.prenom ?? ''} ${u.basic_info?.nom ?? ''} (${date})`.trim();
          })
        };
      },
      error: err => console.error('Erreur chargement utilisateurs', err)
    });
  }

  loadStats(): void {
    this.http.get<any>(apiUrl('/api/statistics')).subscribe({
      next: res => {
        this.stats = res || {};

        const risqueMoyen = Number(res?.risk_moyen ?? 0);
        const nbUtilisateursARisque = Number(res?.nbr_utilisateurs_a_risque ?? 0);
        const pctUtilisateursARisque = Number(res?.pourcentage_utilisateurs_a_risque ?? 0);
        const objectifsAtteints = Number(res?.pourcentage_objectifs_atteints ?? 0);
        // Pourcentage d’utilisateurs avec une formation planifiée (0–100), pas le nombre brut
        const formationsPlanifiees = Number(
          res?.pourcentage_formations_planifiees ??
          res?.pourcentage_formations_planifies ??
          0
        );

        this.score = risqueMoyen * 10;
        this.chartOptions = this.createRadialChart([risqueMoyen], 'riskGlobal');

        // On affiche le pourcentage d'utilisateurs à risque (et non le nombre brut)
        this.scoreRisque = pctUtilisateursARisque;
        this.scoreObjectifs = objectifsAtteints;
        this.scoreFormations = formationsPlanifiees;

        this.chartRisque = this.createRadialChart([pctUtilisateursARisque], 'usersRisk');
        this.chartObjectifs = this.createRadialChart([objectifsAtteints], 'objectives');
        this.chartFormations = this.createRadialChart([formationsPlanifiees], 'trainings');
      },
      error: err => console.error('Erreur chargement stats', err)
    });
  }

  getUserInitial(u: any): string {
    const prenom = u?.basic_info?.prenom;
    const nom = u?.basic_info?.nom;
    const base = (prenom || nom || '').toString().trim();
    if (!base) {
      return '?';
    }
    return base.charAt(0).toUpperCase();
  }

  /**
   * Jauge radiale 0–100 % (alignée sur /api/statistics : pourcentages).
   */
  createRadialChart(series: number[], labelKey: AdminRadialLabelKey): RadialChartOptions {
    const label = this.translate.instant(this.radialLabelKeys[labelKey]);
    const raw = Array.isArray(series) && series.length ? Number(series[0] ?? 0) : 0;
    const clamped = Math.min(100, Math.max(0, Number.isFinite(raw) ? raw : 0));
    const safeSeries = [Math.round(clamped * 10) / 10];
    const value = safeSeries[0];

    // Pour les indicateurs de risque, plus c'est élevé, plus c'est rouge.
    // Pour les indicateurs positifs (objectifs / formations), plus c'est élevé, plus c'est vert.
    let color = '#28a745';
    const isRisque = labelKey === 'riskGlobal' || labelKey === 'usersRisk';

    if (isRisque) {
      if (value >= 70) color = '#d32f2f';       // risque élevé
      else if (value >= 40) color = '#fd7e14';  // risque moyen
      else color = '#28a745';                   // risque faible
    } else {
      if (value >= 70) color = '#28a745';       // bon niveau atteint
      else if (value >= 40) color = '#fd7e14';  // niveau intermédiaire
      else color = '#d32f2f';                   // niveau faible
    }

    return {
      series: safeSeries,
      chart: {
        height: 250,
        type: 'radialBar',
        toolbar: { show: false },
        zoom: { enabled: false }
      },
      plotOptions: {
        // `max` existe dans ApexCharts (échelle 0–100) mais pas dans les types ng-apexcharts → assertion
        radialBar: {
          hollow: { size: '70%' },
          max: 100,
          dataLabels: {
            name: { show: true, fontSize: '16px' },
            value: {
              show: true,
              fontSize: '22px',
              fontWeight: 600,
              color: color,
              /** Valeur série déjà sur échelle 0–100 (stats API) */
              formatter: (val: number) => `${Math.round(val)}%`
            }
          }
        } as ApexPlotOptions['radialBar']
      },
      fill: { type: 'solid', colors: [color] },
      stroke: { lineCap: 'round' },
      labels: [label]
    };
  }

  getRiskBadge(score: number | null): string {
    if (score === null || score === undefined) return 'badge-unknown';
    if (score < 30) return 'badge-low';
    if (score < 70) return 'badge-medium';
    return 'badge-high';
  }

  /**
   * Couleur du risque dans le tableau : si l’objectif n’est pas atteint (Non),
   * le risque est toujours affiché en rouge — prioritaire sur le % seul.
   */
  getRiskBadgeForUser(user: any): string {
    if (!user?.objectifAtteint) {
      return 'badge-high';
    }
    return this.getRiskBadge(this.getDisplayedRisk(user) ?? 0);
  }

  getScoreBadge(score: number): string {
    if (score >= 700) return 'badge-green';
    if (score >= 400) return 'badge-orange';
    return 'badge-red';
  }

  getScoreLabelKey(score: number): string {
    if (score >= 700) return 'ADMIN.SCORE_GOOD';
    if (score >= 400) return 'ADMIN.SCORE_MEDIUM';
    return 'ADMIN.SCORE_LOW';
  }

  get filteredUsers(): any[] {
    
    const usersSansAdmin = this.users.filter(u => u.basic_info?.role !== 'admin');

   let base = usersSansAdmin;

switch (this.filterMode) {
  case 'risk':
    base = base.filter(
      u =>
        (u.riskNormPct ?? 0) >= this.seuilRisque || !u.objectifAtteint
    );
    break;
  case 'noPost':
    base = base.filter(u => u.postQuizManquant);
    break;
  case 'lateTraining':
    base = base.filter(u => u.formationEnRetard);
    break;
  case 'badProfile':
    base = base.filter(u => u.profile_acceptable === false);
    break;
  case 'all':
  default:
    break;
}

if (!this.searchTerm.trim()) return base;

const term = this.searchTerm.toLowerCase();
return base.filter(u =>
  (u.basic_info?.nom || '').toLowerCase().includes(term) ||
  (u.basic_info?.prenom || '').toLowerCase().includes(term) ||
  (u.profil?.jobRole || '').toLowerCase().includes(term) ||
  (u.profil?.qualifications?.join(' ') || '').toLowerCase().includes(term) ||
  (u.profil?.keyResponsibilities?.join(' ') || '').toLowerCase().includes(term)
);
    
  }

  resetRecherche(): void {
    this.searchTerm = '';
  }

  allerVersCreationUtilisateur(): void {
    this.router.navigate(['/creeruser']);
  }

  viewDetails(userID: string): void {
    if (userID) {
      this.router.navigate(['/detailuser', userID]);
    }
  }

  setSection(section: string): void {
    this.activeSection = section;
  }

  /** Onglet admin : charge les métriques depuis le backend */
  selectQuizQualityTab(): void {
    this.activeSection = 'quizQuality';
    this.loadQuizQualityMetrics();
  }

  loadQuizQualityMetrics(): void {
    this.quizQualityLoading = true;
    this.quizQualityError = null;
    this.quizService
      .getQuizQualityMetrics({
        limit: this.qualityLimit,
        userID: this.qualityFilterUserId.trim() || undefined
      })
      .subscribe({
        next: (res) => {
          this.quizQualityItems = res?.items ?? [];
          this.quizQualityLoading = false;
        },
        error: (err) => {
          this.quizQualityError =
            err?.error?.error ||
            err?.message ||
            this.translate.instant('ADMIN.METRICS_LOAD_ERROR');
          this.quizQualityLoading = false;
        }
      });
  }

  downloadQualityCsv(): void {
    const url = this.quizService.buildQuizQualityMetricsCsvUrl({
      limit: this.qualityLimit,
      userID: this.qualityFilterUserId.trim() || undefined
    });
    window.open(url, '_blank');
  }

  /** Accès typé aux champs de quality_metrics pour le template */
  getQm(row: QuizQualityMetricItem | undefined, key: string): unknown {
    const m = row?.quality_metrics;
    if (!m || typeof m !== 'object') return null;
    return (m as Record<string, unknown>)[key];
  }

  /** Pour le pipe `number` (n'accepte pas `unknown`) */
  qmNum(row: QuizQualityMetricItem | undefined, key: string): number | null {
    const v = this.getQm(row, key);
    if (v === null || v === undefined) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  qmBool(row: QuizQualityMetricItem | undefined, key: string): boolean | null {
    const v = this.getQm(row, key);
    if (v === true) return true;
    if (v === false) return false;
    return null;
  }

  getDisplayedRisk(user: any): number | null {
    const value =
      user?.riskNormPct ??
      user?.normalized_risk_score ??
      user?.risk_norm_pct ??
      user?.riskScore ??
      user?.risk_score;

    return value !== undefined && value !== null ? Number(value) : null;
  }

  formatDisplayedRisk(user: any): string {
    const value = this.getDisplayedRisk(user);
    return value !== null ? `${value.toFixed(2)}%` : '-';
  }
}