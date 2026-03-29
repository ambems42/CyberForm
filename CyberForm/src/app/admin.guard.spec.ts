import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { AdminGuard } from './admin.guard';

describe('adminGuard (class)', () => {
  let guard: AdminGuard;
  let routerSpy: jasmine.SpyObj<Router>;

  beforeEach(() => {
    routerSpy = jasmine.createSpyObj('Router', ['navigate']);

    TestBed.configureTestingModule({
      providers: [
        AdminGuard,
        { provide: Router, useValue: routerSpy }
      ]
    });

    guard = TestBed.inject(AdminGuard);
  });

  afterEach(() => localStorage.clear());

  it('should allow access if role is admin', () => {
    localStorage.setItem('role', 'admin');
    expect(guard.canActivate()).toBeTrue();
  });

  it('should deny access and redirect if role is not admin', () => {
    localStorage.setItem('role', 'user');
    expect(guard.canActivate()).toBeFalse();
    expect(routerSpy.navigate).toHaveBeenCalledWith(['/login']);
  });
});
