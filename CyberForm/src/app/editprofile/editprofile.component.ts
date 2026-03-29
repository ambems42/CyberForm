import { Component, OnInit } from '@angular/core';

import { HttpClient } from '@angular/common/http';

import { Router } from '@angular/router';

import { TranslateService } from '@ngx-translate/core';

import { apiUrl } from '../api-url';



@Component({

  selector: 'app-editprofile',

  templateUrl: './editprofile.component.html',

  styleUrls: ['./editprofile.component.css']

})

export class EditProfileComponent implements OnInit {

  userID = '';

  first_name = '';

  last_name = '';

  successMessage = '';

  errorMessage = '';



  constructor(

    private http: HttpClient,

    private router: Router,

    private translate: TranslateService

  ) {}



  ngOnInit(): void {

    const user = JSON.parse(localStorage.getItem('userData') || '{}');

    this.userID = localStorage.getItem('userID') || '';

    this.last_name = user?.nom || '';

    this.first_name = user?.prenom || '';

  }



  updateProfile(): void {

    if (!this.userID) {

      this.errorMessage = this.translate.instant('EDIT_PROFILE.ERR_USERID');

      return;

    }



    const data = {

      userID: this.userID,

      nom: this.last_name,

      prenom: this.first_name

    };



    this.http.post<any>(apiUrl('/api/update_profile'), data).subscribe({

      next: (res) => {

        this.successMessage = res.message || this.translate.instant('EDIT_PROFILE.SUCCESS');

        this.errorMessage = '';



        const userData = JSON.parse(localStorage.getItem('userData') || '{}');

        userData.prenom = this.first_name;

        userData.nom = this.last_name;

        localStorage.setItem('userData', JSON.stringify(userData));



        setTimeout(() => {

          this.router.navigate(['/user']);

        }, 1000);

      },

      error: (err) => {

        this.successMessage = '';

        this.errorMessage = err.error?.error || this.translate.instant('EDIT_PROFILE.ERR_GENERIC');

      }

    });

  }

}

