export const environment = {
  production: false,
  /**
   * Chaîne vide = requêtes relatives ; `ng serve` + proxy.conf.json → Flask :5001.
   * Évite CORS et les erreurs si le front est sur :4200 et l’API sur :5001.
   */
  apiUrl: '',
  /** Adresse du lien « Contact » (footer) : mailto */
  contactEmail: 'support@cyberform.com',
};
