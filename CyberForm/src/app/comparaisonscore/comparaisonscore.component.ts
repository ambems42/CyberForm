import { Component, OnDestroy, OnInit } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';
import { Subscription } from 'rxjs';
import { UserService } from '../user.service';

@Component({
  selector: 'app-comparaisonscore',
  templateUrl: './comparaisonscore.component.html',
  styleUrls: ['./comparaisonscore.component.css']
})
export class ComparaisonscoreComponent implements OnInit, OnDestroy {
  barChartOptions: any = {
    series: [],
    chart: { type: 'bar', height: 350 },
    plotOptions: {
      bar: {
        horizontal: false,
        columnWidth: '50%',
        distributed: true
      }
    },
    dataLabels: { enabled: true },
    xaxis: { categories: [] },
    colors: [],
    responsive: [
      {
        breakpoint: 768,
        options: {
          plotOptions: {
            bar: {
              columnWidth: '60%'
            }
          },
          chart: {
            height: 300
          }
        }
      }
    ]
  };

  private langSub?: Subscription;

  constructor(
    private userService: UserService,
    private translate: TranslateService
  ) {}

  ngOnInit(): void {
    this.loadScores();
    this.langSub = this.translate.onLangChange.subscribe(() => this.loadScores());
  }

  ngOnDestroy(): void {
    this.langSub?.unsubscribe();
  }

  private loadScores(): void {
    this.userService.getUserScores().subscribe({
      next: (data: any[]) => {
        const unknown = this.translate.instant('COMPARISON_SCORE.UNKNOWN_USER');
        const names = data.map(u =>
          u.fullname && u.fullname.trim() ? u.fullname.trim() : u.userID || unknown
        );

        const scores = data.map(u => u.risk_score ?? 0);

        const colors = scores.map((score: number) => {
          if (score > 70) return '#e74c3c';
          else if (score > 30) return '#f39c12';
          else return '#2ecc71';
        });

        this.barChartOptions = {
          ...this.barChartOptions,
          series: [{ name: this.translate.instant('COMPARISON_SCORE.SERIES_RISK'), data: scores }],
          xaxis: {
            ...(this.barChartOptions?.xaxis || {}),
            categories: names
          },
          colors
        };
      },
      error: (err) => {
        console.error('Erreur chargement des scores :', err);
      }
    });
  }
}
