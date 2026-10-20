pipeline {
    agent any
    
    environment {
        // Enforce secure environment variables during build
        JWT_SECRET = credentials('prod-jwt-secret') // Requires Jenkins credentials configuration
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Build & Install') {
            steps {
                bat '''
                python -m venv venv
                call venv\\Scripts\\activate.bat
                pip install -r requirements.txt
                pip install -e external_pkg
                '''
            }
        }
        
        stage('SAST Security Scan (Bandit)') {
            steps {
                bat '''
                call venv\\Scripts\\activate.bat
                bandit -r app_api resource_service processing_service -f json -o reports/bandit_report.json || exit 0
                '''
            }
        }
        
        stage('Dependency Audit') {
            steps {
                bat '''
                call venv\\Scripts\\activate.bat
                pip-audit -r requirements.txt --format json > reports/audit_report.json || exit 0
                '''
            }
        }
        
        stage('Functional & Authorization Tests') {
            steps {
                bat '''
                call venv\\Scripts\\activate.bat
                python resource_service/database.py
                
                start "App" cmd /c "call venv\\Scripts\\activate.bat && python app_api/app.py"
                start "Resource" cmd /c "call venv\\Scripts\\activate.bat && python resource_service/app.py"
                start "Processing" cmd /c "call venv\\Scripts\\activate.bat && python processing_service/app.py"
                
                timeout /t 3 /nobreak >nul
                pytest -v tests/test_vulnerabilities.py > reports/test_results.txt
                
                taskkill /F /IM python.exe /T
                '''
            }
        }
        
        stage('Security Gate Decision') {
            steps {
                script {
                    def banditReport = readJSON file: 'reports/bandit_report.json'
                    def highSeverityCount = banditReport.metrics._totals.SEVERITY.HIGH
                    
                    if (highSeverityCount > 0) {
                        error("GATE FAILED: ${highSeverityCount} High severity vulnerabilities found. Release blocked.")
                    } else {
                        echo "GATE PASSED: No High severity vulnerabilities detected."
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'reports/*.*', allowEmptyArchive: true
        }
    }
}