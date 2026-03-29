import { TestBed } from '@angular/core/testing';
import { CanActivateFn } from '@angular/router';

import { quizAccessGuard } from './quiz-access.guard';

describe('quizAccessGuard', () => {
  const executeGuard: CanActivateFn = (...guardParameters) =>
      TestBed.runInInjectionContext(() => quizAccessGuard(...guardParameters));

  beforeEach(() => {
    TestBed.configureTestingModule({});
  });

  it('should be created', () => {
    expect(executeGuard).toBeTruthy();
  });
});
