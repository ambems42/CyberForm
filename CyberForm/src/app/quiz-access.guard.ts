import { CanActivateFn, Router } from '@angular/router';
import { inject } from '@angular/core';
import { AuthService } from './auth.service';

export const quizAccessGuard: CanActivateFn = () => {
  const router = inject(Router);
  const authService = inject(AuthService);

  const user = authService.getCurrentUser();

  if (!user) {
    router.navigate(['/login']);
    return false;
  }

  // Seul l'utilisateur standard peut accéder au quiz
  if (user.role !== 'utilisateur') {
    router.navigate(['/login']);
    return false;
  }

  // Si l’objectif est atteint, inutile de faire un quiz
  if (user.objectifAtteint) {
    router.navigate(['/user']);
    return false;
  }

  // Si aucun quiz n'a été commencé → autoriser le pré-quiz
  if (!user.quizType || user.quizType === '') {
    return true;
  }

  // Si le pré-quiz est terminé → aller à la formation
  if (user.quizType === 'pre') {
    router.navigate(['/formation']);
    return false;
  }

  // Si le post-quiz est prévu mais l’objectif n’est pas atteint → autoriser le quiz
  if (user.quizType === 'post' && !user.objectifAtteint) {
    return true;
  }

  // Par défaut, bloquer
  router.navigate(['/user']);
  return false;
};
