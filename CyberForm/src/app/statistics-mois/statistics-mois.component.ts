import { Component, OnDestroy, OnInit } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { TranslateService } from '@ngx-translate/core';
import { Subscription } from 'rxjs';
import {
  ApexAxisChartSeries,
  ApexNonAxisChartSeries,
  ApexChart,
  ApexXAxis,
  ApexTitleSubtitle,
  ApexStroke,
  ApexDataLabels
} from 'ng-apexcharts';

type SeriesRow = { name: string; data: number[] };
import { apiUrl } from '../api-url';

export type ChartOptions = {
  series: ApexAxisChartSeries | ApexNonAxisChartSeries;
  chart: ApexChart;
  xaxis: ApexXAxis;
  title: ApexTitleSubtitle;
  stroke: ApexStroke;
  dataLabels: ApexDataLabels;
};

@Component({
  selector: 'app-statistics-mois',
  templateUrl: './statistics-mois.component.html',
  styleUrls: ['./statistics-mois.component.css']
})
export class StatisticsMoisComponent implements OnInit, OnDestroy {
  chartOptions: Partial<ChartOptions> = {
    series: [
      { name: '', data: [] },
      { name: '', data: [] },
      { name: '', data: [] }
    ],
    chart: { type: 'line', height: 350 },
    xaxis: { categories: [] },
    title: { text: '' },
    stroke: { curve: 'smooth' },
    dataLabels: { enabled: false }
  };

  allData: any[] = [];
  filteredData: any[] = [];
  selectedYear: string = '';
  selectedUser: string = '';
  usersList: string[] = [];
  availableYears: string[] = [];
  isLoading = false;
  loadError = '';

  private langSub?: Subscription;

  constructor(
    private http: HttpClient,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {
    this.applySeriesNames();
    this.chartOptions = {
      ...this.chartOptions,
      title: { text: this.translate.instant('STATISTICS_MOIS.CHART_LOADING') }
    };
    this.refreshData();
    this.langSub = this.translate.onLangChange.subscribe(() => {
      this.applySeriesNames();
      this.updateChart();
      if (this.loadError) {
        this.loadError = this.translate.instant('STATISTICS_MOIS.LOAD_ERROR');
      }
    });
  }

  ngOnDestroy(): void {
    this.langSub?.unsubscribe();
  }

  private applySeriesNames(): void {
    const s = this.chartOptions.series as SeriesRow[] | undefined;
    if (!Array.isArray(s) || s.length < 3) return;
    s[0].name = this.translate.instant('STATISTICS_MOIS.SERIES_RISK');
    s[1].name = this.translate.instant('STATISTICS_MOIS.SERIES_OBJECTIVES');
    s[2].name = this.translate.instant('STATISTICS_MOIS.SERIES_TRAININGS');
  }

  private parseMonthYearToDate(mois: string): Date | null {
    if (!mois || typeof mois !== 'string') return null;

    const parts = mois.split('/');
    if (parts.length !== 2) return null;

    const month = Number(parts[0]);
    const year = Number(parts[1]);

    if (!month || !year) return null;

    return new Date(year, month - 1, 1);
  }

  refreshData(): void {
    this.isLoading = true;
    this.loadError = '';

    this.http.get<any[]>(apiUrl('/api/statistics/mois')).subscribe({
      next: (data) => {
        this.allData = (data || []).map(entry => ({
          ...entry,
          dateParsed: this.parseMonthYearToDate(entry.mois)
        }));

        this.extractYears();
        this.extractUsers();
        this.applyFilters();
        this.isLoading = false;
      },
      error: (err) => {
        console.error('Erreur chargement statistiques mensuelles :', err);
        this.allData = [];
        this.filteredData = [];
        this.updateChart();
        this.isLoading = false;
        this.loadError = this.translate.instant('STATISTICS_MOIS.LOAD_ERROR');
      }
    });
  }

  extractYears(): void {
    const years = this.allData
      .map(d => d.mois?.split?.('/')?.[1])
      .filter((y: string) => !!y);

    this.availableYears = [...new Set(years)].sort();
  }

  extractUsers(): void {
    const users = this.allData
      .map(d => d.userID)
      .filter(Boolean);

    this.usersList = [...new Set(users)].sort();
  }

  applyFilters(): void {
    this.filteredData = this.allData.filter(d => {
      const yearMatch = this.selectedYear
        ? d.dateParsed?.getFullYear()?.toString() === this.selectedYear
        : true;

      const userMatch = this.selectedUser
        ? d.userID === this.selectedUser
        : true;

      return yearMatch && userMatch;
    }).sort((a, b) => (a.dateParsed?.getTime() || 0) - (b.dateParsed?.getTime() || 0));

    this.updateChart();
  }

  updateChart(): void {
    if (!this.filteredData || this.filteredData.length === 0) {
      this.chartOptions = {
        series: [
          { name: this.translate.instant('STATISTICS_MOIS.SERIES_RISK'), data: [] },
          { name: this.translate.instant('STATISTICS_MOIS.SERIES_OBJECTIVES'), data: [] },
          { name: this.translate.instant('STATISTICS_MOIS.SERIES_TRAININGS'), data: [] }
        ],
        chart: {
          type: 'line',
          height: 350,
          zoom: { enabled: false },
          toolbar: { show: false }
        },
        title: { text: this.translate.instant('STATISTICS_MOIS.NO_DATA_TITLE') },
        xaxis: { categories: [] },
        stroke: { curve: 'smooth' },
        dataLabels: { enabled: false }
      };
      return;
    }

    const mois = this.filteredData.map(d => d.mois || '');
    const risque = this.filteredData.map(d => Number(d.moyenne_risque ?? 0));
    const objectifs = this.filteredData.map(d => Number(d.objectifs_atteints ?? 0));
    const formations = this.filteredData.map(d => Number(d.formations_planifiees ?? d.formations ?? 0));

    const titleParts = [this.translate.instant('STATISTICS_MOIS.TITLE_BASE')];
    if (this.selectedYear) {
      titleParts.push(this.selectedYear);
    }
    if (this.selectedUser) {
      titleParts.push(
        this.translate.instant('STATISTICS_MOIS.TITLE_USER', { id: this.selectedUser })
      );
    }

    this.chartOptions = {
      chart: {
        type: 'line',
        height: 350,
        zoom: { enabled: false },
        toolbar: { show: false }
      },
      title: { text: titleParts.join(' ') },
      xaxis: { categories: mois },
      stroke: { curve: 'smooth' },
      dataLabels: { enabled: false },
      series: [
        { name: this.translate.instant('STATISTICS_MOIS.SERIES_RISK'), data: risque },
        { name: this.translate.instant('STATISTICS_MOIS.SERIES_OBJECTIVES'), data: objectifs },
        { name: this.translate.instant('STATISTICS_MOIS.SERIES_TRAININGS'), data: formations }
      ]
    };
  }

  hasData(): boolean {
    const series = this.chartOptions.series;
    if (!series || !Array.isArray(series)) return false;

    return series.some(s =>
      s &&
      typeof s === 'object' &&
      'data' in s &&
      Array.isArray((s as any).data) &&
      (s as any).data.length > 0
    );
  }
}