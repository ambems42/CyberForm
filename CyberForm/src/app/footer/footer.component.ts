import { Component } from '@angular/core';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-footer',
  templateUrl: './footer.component.html',
  styleUrl: './footer.component.css'
})
export class FooterComponent {
  /** mailto — défini dans src/environments/environment*.ts */
  readonly contactMailtoHref = `mailto:${environment.contactEmail}`;
}
