import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CreeruserComponent } from './creeruser.component';

describe('CreeruserComponent', () => {
  let component: CreeruserComponent;
  let fixture: ComponentFixture<CreeruserComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [CreeruserComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(CreeruserComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
