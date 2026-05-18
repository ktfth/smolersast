# SmolerSAST — Integração com Jenkins

## Jenkinsfile

```groovy
pipeline {
    agent any

    tools {
        dotnetsdk 'dotnet-9'
    }

    stages {
        stage('Install SmolerSAST') {
            steps {
                sh 'dotnet tool install --global SmolerSAST --version 0.2.0 || true'
            }
        }

        stage('Security Scan') {
            steps {
                sh 'smolersast scan --path ./src --output results.sarif --format both'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.sarif,*.md,manifest.json', fingerprint: true

            // Se usar o plugin Warnings Next Generation:
            recordIssues tools: [sarif(pattern: 'results.sarif')]
        }
    }
}
```

## Plugin Warnings Next Generation

Instale o plugin "Warnings Next Generation" no Jenkins para visualizar os findings SARIF diretamente na interface.
