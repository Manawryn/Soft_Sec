pipeline {
    agent any
    
    environment {
        // Securely injects the credential you created
        JWT_SECRET = credentials('prod-jwt-secret') 
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
                if not exist venv ( python -m venv venv )
                call venv\\Scripts\\activate.bat
                python -m pip install --upgrade pip setuptools wheel
                
                :: Explicitly install pbr to fix the Bandit missing module bug
                pip install pbr
                pip install -r requirements.txt
                pip install -e external_pkg
                
                :: Ensure reports directory exists
                if not exist reports ( mkdir reports )
                '''
            }
        }
        
        stage('SAST Security Scan (Bandit)') {
            steps {
                bat '''
                call venv\\Scripts\\activate.bat
                :: Use backslashes for Windows path redirection
                python -m bandit -r app_api resource_service processing_service -f json -o reports\\bandit_report.json || exit 0
                '''
            }
        }
        
        stage('Dependency Audit') {
            steps {
                bat '''
                call venv\\Scripts\\activate.bat
                :: Use backslashes for Windows path redirection
                python -m pip_audit -r requirements.txt --format json > reports\\audit_report.json || exit 0
                '''
            }
        }
        
        stage('Functional & Authorization Tests') {
            steps {
                bat '''
                call venv\\Scripts\\activate.bat
                python resource_service\\database.py
                
                :: Feed < NUL to stdin to prevent Jenkins headless console crash
                start /B "" cmd /c "python resource_service\\app.py > NUL 2>&1 < NUL"
                start /B "" cmd /c "python processing_service\\app.py > NUL 2>&1 < NUL"
                start /B "" cmd /c "python app_api\\app.py > NUL 2>&1 < NUL"
                
                :: Wait 5 seconds for the servers to boot up
                timeout /t 5 /nobreak >nul
                
                :: Execute the verification suite
                pytest -v tests\\test_vulnerabilities.py > reports\\test_results.txt
                
                :: Gracefully kill background python processes when done
                taskkill /F /IM python.exe /T || exit 0
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