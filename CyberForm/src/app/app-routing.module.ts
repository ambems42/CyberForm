import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';

import { HomeComponent } from './home/home.component';
import { LoginComponent } from './login/login.component';
import { AboutComponent } from './about/about.component';
import { ContactComponent } from './contact/contact.component';
import { PrivacyComponent } from './privacy/privacy.component';
import { SecurityComponent } from './security/security.component';

import { AdminComponent } from './admin/admin.component';
import { UserComponent } from './user/user.component';
import { QuizComponent } from './quiz/quiz.component';
import { FormationComponent } from './formation/formation.component';
import { EditProfileComponent } from './editprofile/editprofile.component';
import { ReviewQuizComponent } from './review-quiz/review-quiz.component';
import { HistoryUserComponent } from './history-user/history-user.component';
import { ResetPasswordComponent } from './reset-password/reset-password.component';
import { ForgotPasswordComponent } from './forgot-password/forgot-password.component';
import { CreeruserComponent } from './creeruser/creeruser.component';
import { DetailuserComponent } from './detailuser/detailuser.component';

import { AuthGuard } from './auth.guard';
import { AdminGuard } from './admin.guard';
import { quizAccessGuard } from './quiz-access.guard';

const routes: Routes = [
  { path: '', component: HomeComponent, pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'about', component: AboutComponent },
  { path: 'contact', component: ContactComponent },
  { path: 'privacy', component: PrivacyComponent },
  { path: 'security', component: SecurityComponent },
  { path: 'review-quiz/:id', component: ReviewQuizComponent },
  { path: 'history-user' , component: HistoryUserComponent},
  { path: 'reset-password', component: ResetPasswordComponent },
  { path: 'forgot-password', component: ForgotPasswordComponent },
  { path: 'creeruser', component: CreeruserComponent },
  { path: 'detailuser/:userID', component: DetailuserComponent },

  { path: 'user', component: UserComponent, canActivate: [AuthGuard] },
  { path: 'editprofile', component: EditProfileComponent, canActivate: [AuthGuard] },
  { path: 'quiz', component: QuizComponent, canActivate: [AuthGuard, quizAccessGuard] },
  { path: 'formation', component: FormationComponent, canActivate: [AuthGuard] },
  { path: 'admin', component: AdminComponent, canActivate: [AdminGuard] },
  { path: 'quiz/:userID', component: QuizComponent },

  { path: '', redirectTo: 'login', pathMatch: 'full'}
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule {}
