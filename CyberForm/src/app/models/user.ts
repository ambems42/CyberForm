export interface QuizHistory {
  type: 'pre' | 'post';
  date: string;
  user_score: number;
  total_questions: number;
  normalized_risk_score: number;
}

export interface User {
  basic_info: {
    userID: string;
    nom: string;
    prenom: string;
    role: 'utilisateur' | 'admin';
    email: string;
    password: string;
  };
  profil: {
    jobRole: string;
    qualifications: string[];       
    keyResponsibilities: string[];   
  };

  createdAt?: string;
  lastEvaluationDate?: string | null;
  lastTrainingDate?: string | null;
  nextEvaluationDate?: string | null;
  nextTrainingDate?: string | null;

  risk_score: number;
  vulnerability_score: number;
  lastTrainingContent?: string;
  objectifAtteint: boolean;
  };
  
