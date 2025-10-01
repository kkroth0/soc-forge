"""
Translation dictionaries for PDF reports
Supports: English (ENG), Brazilian Portuguese (PT-BR), French (FR)
"""

TRANSLATIONS = {
    'ENG': {
        # Cover page
        'title': 'THREAT INTELLIGENCE REPORT',
        'subtitle': 'IP Address Threat Assessment',
        'target_ip': 'Target IP',
        'threat_score': 'Threat Score',
        'date': 'Report Date',
        'classification': 'CONFIDENTIAL - SOC INTERNAL USE',

        # Document control
        'doc_control': 'DOCUMENT CONTROL',
        'version': 'Version',
        'prepared_by': 'Prepared By',
        'reviewed_by': 'Reviewed By',
        'approved_by': 'Approved By',
        'distribution': 'Distribution',
        'purpose': 'Purpose',
        'scope': 'Scope',
        'purpose_text': 'This report provides a comprehensive threat intelligence assessment of the specified IP address, including reputation analysis, threat feed correlation, and DNS blacklist status.',
        'scope_text': 'This assessment covers multiple threat intelligence sources including VirusTotal, AbuseIPDB, GreyNoise, Shodan, IPInfo, AlienVault OTX, DNS Blacklists, and curated threat feeds.',
        'distribution_text': 'SOC Team, Security Analysts, Incident Response Team',
        'soc_analyst': 'SOC Analyst',
        'security_lead': 'Security Lead',
        'soc_manager': 'SOC Manager',

        # Table of contents
        'toc': 'TABLE OF CONTENTS',
        'executive_summary': 'Executive Summary',
        'threat_assessment': 'Threat Assessment Overview',
        'reputation_analysis': 'Reputation Analysis',
        'geographic_info': 'Geographic Information',
        'dnsbl_results': 'DNS Blacklist Results',
        'threat_feeds': 'Threat Feed Correlation',
        'recommendations': 'Recommendations & Actions',
        'methodology': 'Methodology',
        'references': 'References',

        # Executive Summary
        'key_findings': 'Key Findings',
        'overall_assessment': 'Overall Assessment',
        'risk_level': 'Risk Level',
        'detections': 'Detection Summary',
        'recommendation_summary': 'Recommendation Summary',

        # Threat levels
        'CRITICAL': 'CRITICAL',
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'LOW': 'LOW',
        'INFO': 'INFORMATIONAL',

        # Threat Assessment
        'threat_overview': 'THREAT ASSESSMENT OVERVIEW',
        'scoring_table': 'Threat Scoring Breakdown',
        'source': 'Source',
        'status': 'Status',
        'score_contribution': 'Score Contribution',
        'details': 'Details',
        'detected': 'Detected',
        'clean': 'Clean',
        'not_available': 'Not Available',

        # Reputation Analysis
        'reputation_title': 'REPUTATION ANALYSIS',
        'reputation_summary': 'Multi-Source Reputation Summary',
        'findings': 'Findings',

        # Geographic Information
        'geographic_title': 'GEOGRAPHIC INFORMATION',
        'location': 'Location',
        'organization': 'Organization',
        'asn': 'ASN',
        'timezone': 'Timezone',
        'country': 'Country',
        'city': 'City',
        'region': 'Region',
        'unknown': 'Unknown',
        'not_found': 'Not Found',

        # DNSBL
        'dnsbl_title': 'DNS BLACKLIST RESULTS',
        'dnsbl_summary': 'DNSBL Summary',
        'total_checked': 'Total DNSBLs Checked',
        'blacklisted': 'Blacklisted In',
        'whitelisted': 'Whitelisted In',
        'threat_level': 'Threat Level',
        'blacklist_entries': 'Blacklist Entries',
        'whitelist_entries': 'Whitelist Entries',
        'dnsbl_name': 'DNSBL Name',
        'category': 'Category',
        'description': 'Description',
        'no_listings': 'No blacklist entries found',
        'no_whitelist': 'No whitelist entries found',

        # Threat Feeds
        'feeds_title': 'THREAT FEED CORRELATION',
        'feeds_summary': 'Threat Feed Summary',
        'total_feeds': 'Total Feeds Checked',
        'matches_found': 'Matches Found',
        'feed_categories': 'Feed Categories',
        'matched_feeds': 'Matched Threat Feeds',
        'feed_name': 'Feed Name',
        'feed_type': 'Type',
        'no_feeds': 'IP not found in any threat intelligence feeds',

        # Recommendations
        'recommendations_title': 'RECOMMENDATIONS & ACTION ITEMS',
        'immediate_actions': 'Immediate Actions',
        'monitoring': 'Monitoring',
        'investigation': 'Investigation',

        # Recommendations by threat level
        'rec_critical': [
            'IMMEDIATE BLOCKING: Block this IP address at perimeter firewalls',
            'INCIDENT RESPONSE: Initiate incident response procedures',
            'FORENSICS: Collect and preserve evidence of any connections',
            'THREAT HUNTING: Search for indicators of compromise across environment',
            'ESCALATION: Notify CISO and relevant stakeholders immediately'
        ],
        'rec_high': [
            'Block this IP address at network perimeter',
            'Review all logs for connections from this IP in the last 90 days',
            'Monitor for any future connection attempts',
            'Add to threat intelligence platform for correlation',
            'Consider adding to SIEM watchlists'
        ],
        'rec_medium': [
            'Add IP to monitoring watchlist',
            'Review recent connection logs',
            'Enable enhanced logging for this IP',
            'Consider rate limiting if connections are observed',
            'Schedule follow-up review in 30 days'
        ],
        'rec_low': [
            'Monitor for suspicious activity',
            'Log connections for analysis',
            'No immediate blocking required',
            'Review during regular threat intelligence updates'
        ],

        # Methodology
        'methodology_title': 'METHODOLOGY',
        'data_collection': 'Data Collection',
        'data_collection_text': 'This assessment aggregates data from multiple authoritative threat intelligence sources including commercial APIs, open-source intelligence feeds, and community-driven blacklists. Each source is queried in real-time to ensure the most current threat information.',
        'analysis_framework': 'Analysis Framework',
        'analysis_framework_text': 'The analysis employs a multi-dimensional framework that evaluates:',
        'analysis_points': [
            'Historical malicious activity and abuse reports',
            'Current presence in threat intelligence feeds and blacklists',
            'Network infrastructure and hosting provider reputation',
            'Geographic and organizational context',
            'Community-contributed intelligence and threat sharing platforms'
        ],
        'scoring_methodology': 'Threat Scoring Methodology',
        'scoring_methodology_text': 'The overall threat score (0-100) is calculated using a weighted algorithm that considers:',
        'scoring_points': [
            'VirusTotal detections and reputation score (20% weight)',
            'AbuseIPDB confidence score and report history (20% weight)',
            'Threat feed matches and categories (25% weight)',
            'DNS blacklist presence and threat level (20% weight)',
            'Additional intelligence source indicators (15% weight)'
        ],
        'limitations': 'Limitations',
        'limitations_text': 'This assessment represents a point-in-time analysis. Threat intelligence is dynamic and subject to change. False positives may occur, and absence of malicious indicators does not guarantee benign intent. This report should be used in conjunction with other security controls and analyst judgment.',

        # References
        'references_title': 'REFERENCES & DATA SOURCES',
        'data_sources': 'Data Sources',
        'tool': 'Tool',
        'url': 'URL',
        'footer_page': 'Page',
        'footer_of': 'of',
    },

    'PT-BR': {
        # Cover page
        'title': 'RELATÓRIO DE INTELIGÊNCIA DE AMEAÇAS',
        'subtitle': 'Avaliação de Ameaças de Endereço IP',
        'target_ip': 'IP Alvo',
        'threat_score': 'Pontuação de Ameaça',
        'date': 'Data do Relatório',
        'classification': 'CONFIDENCIAL - USO INTERNO SOC',

        # Document control
        'doc_control': 'CONTROLE DE DOCUMENTO',
        'version': 'Versão',
        'prepared_by': 'Preparado Por',
        'reviewed_by': 'Revisado Por',
        'approved_by': 'Aprovado Por',
        'distribution': 'Distribuição',
        'purpose': 'Propósito',
        'scope': 'Escopo',
        'purpose_text': 'Este relatório fornece uma avaliação abrangente de inteligência de ameaças do endereço IP especificado, incluindo análise de reputação, correlação de feeds de ameaças e status de listas negras DNS.',
        'scope_text': 'Esta avaliação abrange múltiplas fontes de inteligência de ameaças, incluindo VirusTotal, AbuseIPDB, GreyNoise, Shodan, IPInfo, AlienVault OTX, Listas Negras DNS e feeds de ameaças curados.',
        'distribution_text': 'Equipe SOC, Analistas de Segurança, Equipe de Resposta a Incidentes',
        'soc_analyst': 'Analista SOC',
        'security_lead': 'Líder de Segurança',
        'soc_manager': 'Gerente SOC',

        # Table of contents
        'toc': 'ÍNDICE',
        'executive_summary': 'Sumário Executivo',
        'threat_assessment': 'Visão Geral da Avaliação de Ameaças',
        'reputation_analysis': 'Análise de Reputação',
        'geographic_info': 'Informações Geográficas',
        'dnsbl_results': 'Resultados de Listas Negras DNS',
        'threat_feeds': 'Correlação de Feeds de Ameaças',
        'recommendations': 'Recomendações e Ações',
        'methodology': 'Metodologia',
        'references': 'Referências',

        # Executive Summary
        'key_findings': 'Principais Descobertas',
        'overall_assessment': 'Avaliação Geral',
        'risk_level': 'Nível de Risco',
        'detections': 'Resumo de Detecções',
        'recommendation_summary': 'Resumo de Recomendações',

        # Threat levels
        'CRITICAL': 'CRÍTICO',
        'HIGH': 'ALTO',
        'MEDIUM': 'MÉDIO',
        'LOW': 'BAIXO',
        'INFO': 'INFORMATIVO',

        # Threat Assessment
        'threat_overview': 'VISÃO GERAL DA AVALIAÇÃO DE AMEAÇAS',
        'scoring_table': 'Detalhamento da Pontuação de Ameaças',
        'source': 'Fonte',
        'status': 'Status',
        'score_contribution': 'Contribuição da Pontuação',
        'details': 'Detalhes',
        'detected': 'Detectado',
        'clean': 'Limpo',
        'not_available': 'Não Disponível',

        # Reputation Analysis
        'reputation_title': 'ANÁLISE DE REPUTAÇÃO',
        'reputation_summary': 'Resumo de Reputação de Múltiplas Fontes',
        'findings': 'Descobertas',

        # Geographic Information
        'geographic_title': 'INFORMAÇÕES GEOGRÁFICAS',
        'location': 'Localização',
        'organization': 'Organização',
        'asn': 'ASN',
        'timezone': 'Fuso Horário',
        'country': 'País',
        'city': 'Cidade',
        'region': 'Região',
        'unknown': 'Desconhecido',
        'not_found': 'Não Encontrado',

        # DNSBL
        'dnsbl_title': 'RESULTADOS DE LISTAS NEGRAS DNS',
        'dnsbl_summary': 'Resumo DNSBL',
        'total_checked': 'Total de DNSBLs Verificadas',
        'blacklisted': 'Na Lista Negra',
        'whitelisted': 'Na Lista Branca',
        'threat_level': 'Nível de Ameaça',
        'blacklist_entries': 'Entradas na Lista Negra',
        'whitelist_entries': 'Entradas na Lista Branca',
        'dnsbl_name': 'Nome DNSBL',
        'category': 'Categoria',
        'description': 'Descrição',
        'no_listings': 'Nenhuma entrada de lista negra encontrada',
        'no_whitelist': 'Nenhuma entrada de lista branca encontrada',

        # Threat Feeds
        'feeds_title': 'CORRELAÇÃO DE FEEDS DE AMEAÇAS',
        'feeds_summary': 'Resumo de Feeds de Ameaças',
        'total_feeds': 'Total de Feeds Verificados',
        'matches_found': 'Correspondências Encontradas',
        'feed_categories': 'Categorias de Feed',
        'matched_feeds': 'Feeds de Ameaças Correspondentes',
        'feed_name': 'Nome do Feed',
        'feed_type': 'Tipo',
        'no_feeds': 'IP não encontrado em nenhum feed de inteligência de ameaças',

        # Recommendations
        'recommendations_title': 'RECOMENDAÇÕES E ITENS DE AÇÃO',
        'immediate_actions': 'Ações Imediatas',
        'monitoring': 'Monitoramento',
        'investigation': 'Investigação',

        # Recommendations by threat level
        'rec_critical': [
            'BLOQUEIO IMEDIATO: Bloquear este endereço IP nos firewalls de perímetro',
            'RESPOSTA A INCIDENTES: Iniciar procedimentos de resposta a incidentes',
            'FORENSE: Coletar e preservar evidências de quaisquer conexões',
            'CAÇA À AMEAÇAS: Buscar indicadores de comprometimento em todo o ambiente',
            'ESCALAÇÃO: Notificar CISO e stakeholders relevantes imediatamente'
        ],
        'rec_high': [
            'Bloquear este endereço IP no perímetro da rede',
            'Revisar todos os logs de conexões deste IP nos últimos 90 dias',
            'Monitorar quaisquer tentativas futuras de conexão',
            'Adicionar à plataforma de inteligência de ameaças para correlação',
            'Considerar adicionar às listas de observação do SIEM'
        ],
        'rec_medium': [
            'Adicionar IP à lista de monitoramento',
            'Revisar logs de conexão recentes',
            'Habilitar registro aprimorado para este IP',
            'Considerar limitação de taxa se conexões forem observadas',
            'Agendar revisão de acompanhamento em 30 dias'
        ],
        'rec_low': [
            'Monitorar atividade suspeita',
            'Registrar conexões para análise',
            'Bloqueio imediato não é necessário',
            'Revisar durante atualizações regulares de inteligência de ameaças'
        ],

        # Methodology
        'methodology_title': 'METODOLOGIA',
        'data_collection': 'Coleta de Dados',
        'data_collection_text': 'Esta avaliação agrega dados de múltiplas fontes autorizadas de inteligência de ameaças, incluindo APIs comerciais, feeds de inteligência de código aberto e listas negras orientadas pela comunidade. Cada fonte é consultada em tempo real para garantir as informações de ameaças mais atuais.',
        'analysis_framework': 'Framework de Análise',
        'analysis_framework_text': 'A análise emprega um framework multidimensional que avalia:',
        'analysis_points': [
            'Atividade maliciosa histórica e relatórios de abuso',
            'Presença atual em feeds de inteligência de ameaças e listas negras',
            'Infraestrutura de rede e reputação do provedor de hospedagem',
            'Contexto geográfico e organizacional',
            'Inteligência contribuída pela comunidade e plataformas de compartilhamento de ameaças'
        ],
        'scoring_methodology': 'Metodologia de Pontuação de Ameaças',
        'scoring_methodology_text': 'A pontuação geral de ameaça (0-100) é calculada usando um algoritmo ponderado que considera:',
        'scoring_points': [
            'Detecções e pontuação de reputação do VirusTotal (peso de 20%)',
            'Pontuação de confiança e histórico de relatórios do AbuseIPDB (peso de 20%)',
            'Correspondências e categorias de feeds de ameaças (peso de 25%)',
            'Presença em listas negras DNS e nível de ameaça (peso de 20%)',
            'Indicadores de fontes de inteligência adicionais (peso de 15%)'
        ],
        'limitations': 'Limitações',
        'limitations_text': 'Esta avaliação representa uma análise pontual. A inteligência de ameaças é dinâmica e sujeita a mudanças. Falsos positivos podem ocorrer, e a ausência de indicadores maliciosos não garante intenção benigna. Este relatório deve ser usado em conjunto com outros controles de segurança e julgamento do analista.',

        # References
        'references_title': 'REFERÊNCIAS E FONTES DE DADOS',
        'data_sources': 'Fontes de Dados',
        'tool': 'Ferramenta',
        'url': 'URL',
        'footer_page': 'Página',
        'footer_of': 'de',
    },

    'FR': {
        # Cover page
        'title': 'RAPPORT DE RENSEIGNEMENT SUR LES MENACES',
        'subtitle': 'Évaluation des Menaces d\'Adresse IP',
        'target_ip': 'IP Cible',
        'threat_score': 'Score de Menace',
        'date': 'Date du Rapport',
        'classification': 'CONFIDENTIEL - USAGE INTERNE SOC',

        # Document control
        'doc_control': 'CONTRÔLE DU DOCUMENT',
        'version': 'Version',
        'prepared_by': 'Préparé Par',
        'reviewed_by': 'Révisé Par',
        'approved_by': 'Approuvé Par',
        'distribution': 'Distribution',
        'purpose': 'Objectif',
        'scope': 'Portée',
        'purpose_text': 'Ce rapport fournit une évaluation complète du renseignement sur les menaces de l\'adresse IP spécifiée, incluant l\'analyse de réputation, la corrélation des flux de menaces et le statut des listes noires DNS.',
        'scope_text': 'Cette évaluation couvre plusieurs sources de renseignement sur les menaces, notamment VirusTotal, AbuseIPDB, GreyNoise, Shodan, IPInfo, AlienVault OTX, les listes noires DNS et les flux de menaces organisés.',
        'distribution_text': 'Équipe SOC, Analystes de Sécurité, Équipe de Réponse aux Incidents',
        'soc_analyst': 'Analyste SOC',
        'security_lead': 'Responsable Sécurité',
        'soc_manager': 'Gestionnaire SOC',

        # Table of contents
        'toc': 'TABLE DES MATIÈRES',
        'executive_summary': 'Résumé Exécutif',
        'threat_assessment': 'Aperçu de l\'Évaluation des Menaces',
        'reputation_analysis': 'Analyse de Réputation',
        'geographic_info': 'Informations Géographiques',
        'dnsbl_results': 'Résultats des Listes Noires DNS',
        'threat_feeds': 'Corrélation des Flux de Menaces',
        'recommendations': 'Recommandations et Actions',
        'methodology': 'Méthodologie',
        'references': 'Références',

        # Executive Summary
        'key_findings': 'Principales Conclusions',
        'overall_assessment': 'Évaluation Générale',
        'risk_level': 'Niveau de Risque',
        'detections': 'Résumé des Détections',
        'recommendation_summary': 'Résumé des Recommandations',

        # Threat levels
        'CRITICAL': 'CRITIQUE',
        'HIGH': 'ÉLEVÉ',
        'MEDIUM': 'MOYEN',
        'LOW': 'FAIBLE',
        'INFO': 'INFORMATIF',

        # Threat Assessment
        'threat_overview': 'APERÇU DE L\'ÉVALUATION DES MENACES',
        'scoring_table': 'Répartition du Score de Menace',
        'source': 'Source',
        'status': 'Statut',
        'score_contribution': 'Contribution au Score',
        'details': 'Détails',
        'detected': 'Détecté',
        'clean': 'Propre',
        'not_available': 'Non Disponible',

        # Reputation Analysis
        'reputation_title': 'ANALYSE DE RÉPUTATION',
        'reputation_summary': 'Résumé de Réputation Multi-Sources',
        'findings': 'Conclusions',

        # Geographic Information
        'geographic_title': 'INFORMATIONS GÉOGRAPHIQUES',
        'location': 'Localisation',
        'organization': 'Organisation',
        'asn': 'ASN',
        'timezone': 'Fuseau Horaire',
        'country': 'Pays',
        'city': 'Ville',
        'region': 'Région',
        'unknown': 'Inconnu',
        'not_found': 'Non Trouvé',

        # DNSBL
        'dnsbl_title': 'RÉSULTATS DES LISTES NOIRES DNS',
        'dnsbl_summary': 'Résumé DNSBL',
        'total_checked': 'Total de DNSBL Vérifiées',
        'blacklisted': 'En Liste Noire',
        'whitelisted': 'En Liste Blanche',
        'threat_level': 'Niveau de Menace',
        'blacklist_entries': 'Entrées en Liste Noire',
        'whitelist_entries': 'Entrées en Liste Blanche',
        'dnsbl_name': 'Nom DNSBL',
        'category': 'Catégorie',
        'description': 'Description',
        'no_listings': 'Aucune entrée en liste noire trouvée',
        'no_whitelist': 'Aucune entrée en liste blanche trouvée',

        # Threat Feeds
        'feeds_title': 'CORRÉLATION DES FLUX DE MENACES',
        'feeds_summary': 'Résumé des Flux de Menaces',
        'total_feeds': 'Total de Flux Vérifiés',
        'matches_found': 'Correspondances Trouvées',
        'feed_categories': 'Catégories de Flux',
        'matched_feeds': 'Flux de Menaces Correspondants',
        'feed_name': 'Nom du Flux',
        'feed_type': 'Type',
        'no_feeds': 'IP non trouvée dans aucun flux de renseignement sur les menaces',

        # Recommendations
        'recommendations_title': 'RECOMMANDATIONS ET ACTIONS',
        'immediate_actions': 'Actions Immédiates',
        'monitoring': 'Surveillance',
        'investigation': 'Enquête',

        # Recommendations by threat level
        'rec_critical': [
            'BLOCAGE IMMÉDIAT: Bloquer cette adresse IP sur les pare-feux de périmètre',
            'RÉPONSE AUX INCIDENTS: Initier les procédures de réponse aux incidents',
            'FORENSIQUE: Collecter et préserver les preuves de toute connexion',
            'CHASSE AUX MENACES: Rechercher les indicateurs de compromission dans l\'environnement',
            'ESCALADE: Notifier le RSSI et les parties prenantes concernées immédiatement'
        ],
        'rec_high': [
            'Bloquer cette adresse IP au périmètre du réseau',
            'Examiner tous les journaux de connexions de cette IP au cours des 90 derniers jours',
            'Surveiller toute tentative de connexion future',
            'Ajouter à la plateforme de renseignement sur les menaces pour corrélation',
            'Envisager l\'ajout aux listes de surveillance SIEM'
        ],
        'rec_medium': [
            'Ajouter l\'IP à la liste de surveillance',
            'Examiner les journaux de connexion récents',
            'Activer la journalisation améliorée pour cette IP',
            'Envisager la limitation du taux si des connexions sont observées',
            'Planifier un examen de suivi dans 30 jours'
        ],
        'rec_low': [
            'Surveiller l\'activité suspecte',
            'Journaliser les connexions pour analyse',
            'Aucun blocage immédiat requis',
            'Examiner lors des mises à jour régulières du renseignement sur les menaces'
        ],

        # Methodology
        'methodology_title': 'MÉTHODOLOGIE',
        'data_collection': 'Collecte de Données',
        'data_collection_text': 'Cette évaluation agrège des données provenant de plusieurs sources autoritaires de renseignement sur les menaces, notamment des API commerciales, des flux de renseignement open source et des listes noires communautaires. Chaque source est interrogée en temps réel pour garantir les informations les plus récentes sur les menaces.',
        'analysis_framework': 'Cadre d\'Analyse',
        'analysis_framework_text': 'L\'analyse emploie un cadre multidimensionnel qui évalue:',
        'analysis_points': [
            'Activité malveillante historique et rapports d\'abus',
            'Présence actuelle dans les flux de renseignement sur les menaces et les listes noires',
            'Infrastructure réseau et réputation du fournisseur d\'hébergement',
            'Contexte géographique et organisationnel',
            'Renseignement communautaire et plateformes de partage de menaces'
        ],
        'scoring_methodology': 'Méthodologie de Score de Menace',
        'scoring_methodology_text': 'Le score de menace global (0-100) est calculé en utilisant un algorithme pondéré qui considère:',
        'scoring_points': [
            'Détections VirusTotal et score de réputation (pondération de 20%)',
            'Score de confiance AbuseIPDB et historique des rapports (pondération de 20%)',
            'Correspondances et catégories de flux de menaces (pondération de 25%)',
            'Présence en liste noire DNS et niveau de menace (pondération de 20%)',
            'Indicateurs de sources de renseignement supplémentaires (pondération de 15%)'
        ],
        'limitations': 'Limitations',
        'limitations_text': 'Cette évaluation représente une analyse ponctuelle. Le renseignement sur les menaces est dynamique et sujet à changement. Des faux positifs peuvent survenir, et l\'absence d\'indicateurs malveillants ne garantit pas une intention bénigne. Ce rapport doit être utilisé en conjonction avec d\'autres contrôles de sécurité et le jugement de l\'analyste.',

        # References
        'references_title': 'RÉFÉRENCES ET SOURCES DE DONNÉES',
        'data_sources': 'Sources de Données',
        'tool': 'Outil',
        'url': 'URL',
        'footer_page': 'Page',
        'footer_of': 'de',
    }
}


def get_translation(language: str, key: str, default: str = None) -> str:
    """
    Get translation for a given key in specified language

    Args:
        language: Language code (ENG, PT-BR, FR)
        key: Translation key
        default: Default value if key not found

    Returns:
        Translated string or default
    """
    lang = language.upper()
    if lang not in TRANSLATIONS:
        lang = 'ENG'

    return TRANSLATIONS[lang].get(key, default or key)
