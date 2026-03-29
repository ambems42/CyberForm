import { ComponentFixture, TestBed } from '@angular/core/testing';

import { StatisticsMoisComponent } from './statistics-mois.component';

describe('StatisticsMoisComponent', () => {
  let component: StatisticsMoisComponent;
  let fixture: ComponentFixture<StatisticsMoisComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [StatisticsMoisComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(StatisticsMoisComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
