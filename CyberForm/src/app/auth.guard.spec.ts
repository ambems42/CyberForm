import { TestBed } from '@angular/core/testing';
import { AuthGuard } from './auth.guard';
import { Router } from '@angular/router';
import { RouterTestingModule } from '@angular/router/testing';

describe('AuthGuard', () => {
  let guard: AuthGuard;
  let router: Router;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [RouterTestingModule]
    });
    guard = TestBed.inject(AuthGuard);
    router = TestBed.inject(Router);
  });

  afterEach(() => {
    localStorage.clear();
  });

  it('devrait autoriser si isConnected = true', () => {
    localStorage.setItem('isConnected', 'true');
    expect(guard.canActivate()).toBeTrue();
  });

  it('devrait bloquer et rediriger si non connecté', () => {
    spyOn(router, 'navigate');
    localStorage.setItem('isConnected', 'false');

    expect(guard.canActivate()).toBeFalse();
    expect(router.navigate).toHaveBeenCalledWith(['/login']);
  });
});
