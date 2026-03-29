import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ComparaisonscoreComponent } from './comparaisonscore.component';

describe('ComparaisonscoreComponent', () => {
  let component: ComparaisonscoreComponent;
  let fixture: ComponentFixture<ComparaisonscoreComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ComparaisonscoreComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(ComparaisonscoreComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
