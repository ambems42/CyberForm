import { Component } from '@angular/core';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrl: './home.component.css'
})
export class HomeComponent {
testimonials = [
    {
      name: 'Marie Dupont',
      role: 'Chargée de conformité',
      comment: "CyberForm m'a permis de comprendre mes failles en sécurité. Les formations sont simples, pratiques et ciblées."
    },
    {
      name: 'Ali Ben Youssef',
      role: 'Développeur Web',
      comment: "J'ai adoré la personnalisation des quiz. C'est motivant et surtout très formateur."
    },
    {
      name: 'Clara Lopez',
      role: 'Responsable RH',
      comment: "Une interface claire, un suivi précis du risque. CyberForm a transformé notre sensibilisation."
    }
  ];
}
