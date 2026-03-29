import { Injectable } from '@angular/core';
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpErrorResponse,
} from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { Router } from '@angular/router';

/**
 * Bearer JWT + gestion 401 (sans dépendre d'AuthService pour éviter une dépendance circulaire HttpClient).
 */
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private router: Router) {}

  intercept(
    req: HttpRequest<unknown>,
    next: HttpHandler
  ): Observable<HttpEvent<unknown>> {
    const publicPaths = ['/login', '/request-reset', '/reset-password', '/api/contact'];
    const isPublic = publicPaths.some((p) => req.url.includes(p));
    let clone = req.clone({ withCredentials: true });
    if (!isPublic) {
      const token =
        localStorage.getItem('access_token') ||
        sessionStorage.getItem('access_token');
      if (token) {
        clone = clone.clone({
          setHeaders: { Authorization: `Bearer ${token}` },
        });
      }
    }
    return next.handle(clone).pipe(
      catchError((err: HttpErrorResponse) => {
        if (err.status === 401 && !req.url.includes('/login')) {
          localStorage.clear();
          sessionStorage.clear();
          this.router.navigate(['/login']);
        }
        return throwError(() => err);
      })
    );
  }
}
