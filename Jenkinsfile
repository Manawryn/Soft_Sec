pipeline {
    agent any
    triggers { pollSCM('H/2 * * * *') }   // localhost can't receive GitHub webhooks
    environment { JWT_SECRET = credentials('prod-jwt-secret') }

    stages {
        stage('Checkout') {
            steps { deleteDir(); checkout scm }   // fresh workspace: no stale DB or venv
        }
        stage('Build & Install') {
            steps {
                bat '''
                python -m venv venv
                call venv\\Scripts\\activate.bat
                python -m pip install --upgrade pip setuptools wheel
                pip install pbr
                pip install -r requirements.txt
                pip install -e external_pkg
                mkdir reports
                '''
            }
        }
        stage('SAST (Bandit)') {
            steps {
                bat '''
                call venv\\Scripts\\activate.bat
                python -m bandit -r app_api resource_service processing_service -f json -o reports\\bandit_report.json || exit /b 0
                '''
            }
        }
        stage('Dependency Audit (SCA)') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    timeout(time: 5, unit: 'MINUTES') {
                        bat '''
                        call venv\\Scripts\\activate.bat
                        python -m pip_audit --local --timeout 30 -f json -o reports\\pip_audit.json
                        '''
                    }
                }
            }
        }
        stage('Functional & Authorization Tests') {
            steps {
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    bat '''
                    call venv\\Scripts\\activate.bat
                    python -m pytest -v --junitxml=reports\\junit.xml > reports\\test_results.txt 2>&1
                    set RC=%ERRORLEVEL%
                    type reports\\test_results.txt
                    exit /b %RC%
                    '''
                }
            }
        }
        stage('Security Gate') {
            steps {
                bat '''
                call venv\\Scripts\\activate.bat
                python ci\\security_gate.py
                '''
            }
        }
    }
    post {
        always {
            junit allowEmptyResults: true, testResults: 'reports/junit.xml'
            archiveArtifacts artifacts: 'reports/*.*', allowEmptyArchive: true
        }
    }
}