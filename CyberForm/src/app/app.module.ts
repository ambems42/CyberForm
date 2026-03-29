import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { BrowserModule } from '@angular/platform-browser';
import { RouterModule } from '@angular/router';
import {
  HttpClientModule,
  HttpClient,
  HTTP_INTERCEPTORS,
} from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { NgApexchartsModule } from 'ng-apexcharts';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { HeaderComponent } from './header/header.component';
import { FooterComponent } from './footer/footer.component';
import { AboutComponent } from './about/about.component';
import { ContactComponent } from './contact/contact.component';
import { PrivacyComponent } from './privacy/privacy.component';
import { LoginComponent } from './login/login.component';
import { AdminComponent } from './admin/admin.component';
import { UserComponent } from './user/user.component';
import { QuizComponent } from './quiz/quiz.component';
import { FormationComponent } from './formation/formation.component';
import { SecurityComponent } from './security/security.component';
import { HomeComponent } from './home/home.component';
import { EditProfileComponent } from './editprofile/editprofile.component';

import { TranslateModule, TranslateLoader } from '@ngx-translate/core';
import { TranslateHttpLoader } from '@ngx-translate/http-loader';
import { ReviewQuizComponent } from './review-quiz/review-quiz.component';
import { ResetPasswordComponent } from './reset-password/reset-password.component';
import { ForgotPasswordComponent } from './forgot-password/forgot-password.component';
import { HistoryUserComponent } from './history-user/history-user.component';
import { CreeruserComponent } from './creeruser/creeruser.component';
import { DetailuserComponent } from './detailuser/detailuser.component';
import { ComparaisonscoreComponent } from './comparaisonscore/comparaisonscore.component';
import { StatisticsMoisComponent } from './statistics-mois/statistics-mois.component';
import { SafeHtmlPipe } from './pipes/safe-html.pipe';
import { AuthInterceptor } from './auth.interceptor';

// Fonction pour charger les fichiers JSON
export function HttpLoaderFactory(http: HttpClient) {
  return new TranslateHttpLoader(http, './assets/i18n/', '.json');
}

@NgModule({
  declarations: [
    AppComponent,
    HeaderComponent,
    FooterComponent,
    AboutComponent,
    ContactComponent,
    PrivacyComponent,
    LoginComponent,
    AdminComponent,
    UserComponent,
    QuizComponent,
    FormationComponent,
    SecurityComponent,
    HomeComponent,
    EditProfileComponent,
    ReviewQuizComponent,
    ResetPasswordComponent,
    ForgotPasswordComponent,
    HistoryUserComponent,
    CreeruserComponent,
    DetailuserComponent,
    ComparaisonscoreComponent,
    StatisticsMoisComponent,
    SafeHtmlPipe,
  ],

  imports: [
    BrowserModule,
    AppRoutingModule,
    RouterModule,
    HttpClientModule,
    CommonModule,
    NgApexchartsModule,
    FormsModule,

    // Ajout de ngx-translate
    TranslateModule.forRoot({
      loader: {
        provide: TranslateLoader,
        useFactory: HttpLoaderFactory,
        deps: [HttpClient]
      }
    })
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true },
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
