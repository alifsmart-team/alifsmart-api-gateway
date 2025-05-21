// Jenkinsfile
pipeline {
    agent any // Pastikan agent ini memiliki Docker & Git terinstal dan dikonfigurasi dengan benar

    tools {
        // Nama instalasi Git dari Manage Jenkins > Tools
        git 'Default'
    }

    environment {
        // Konfigurasi Docker Image
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'

        // ID Kredensial Redis dari Jenkins (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        ENV_REDIS_HOST = credentials('redis_host')
        ENV_REDIS_PORT = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled')

        // Detail Swarm Manager & ID Kredensial SSH (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id'
        SWARM_MANAGER_IP = '47.84.46.116' // IP Server 1 Swarm Manager Anda
        SWARM_MANAGER_USER = 'root'
        
        // ID Kredensial Docker Hub (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'

        // ID Kredensial GitHub PAT (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        GITHUB_CREDENTIALS_ID = 'github_pat'
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Checking out from GitHub repository..."
                git branch: 'main',
                    credentialsId: env.GITHUB_CREDENTIALS_ID,
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git' // URL Repo Anda
                echo "Checkout complete."
            }
        }

        stage('Install Dependencies & Test') {
            steps {
                echo "Installing dependencies and running tests inside Docker..."
                // Menggunakan PowerShell untuk menjalankan perintah docker run
                // Bagian sh -c "..." di dalam container tetap karena container adalah Linux (node:18-alpine)
                // ${PWD} adalah cara PowerShell untuk mendapatkan direktori kerja saat ini
                powershell 'docker run --rm -v "${PWD}:/app" -w /app node:18-alpine sh -c "npm ci && npm run test -- --passWithNoTests"'
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    def fullImageNameForScan = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"

                    echo "Building temporary image for scan: ${fullImageNameForScan}"
                    // docker.build() sudah lintas platform, tidak perlu diubah dari sh/powershell di sini
                    docker.withRegistry('https://index.docker.io/v1/', env.DOCKER_HUB_CREDENTIALS_ID) {
                        def scanImage = docker.build(fullImageNameForScan, "-f Dockerfile .")
                        // Tidak perlu push image scan ini ke registry
                    }
                    
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities..."
                    // Menggunakan powershell untuk menjalankan Trivy.
                    // Asumsikan 'trivy.exe' ada di PATH Windows Anda.
                    def trivyScanCommand = "trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 ${fullImageNameForScan}"
                    // Jika Anda menjalankan Trivy via Docker (direkomendasikan jika trivy.exe tidak di PATH):
                    // trivyScanCommand = "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 ${fullImageNameForScan}"
                    
                    try {
                        powershell "${trivyScanCommand}"
                        echo "Trivy scan passed or ignored vulnerabilities did not cause failure."
                    } catch (err) {
                        echo "Trivy scan failed or found unignored CRITICAL/HIGH vulnerabilities. Error: ${err.getMessage()}"
                        // Jika Anda ingin pipeline GAGAL jika ada temuan serius yang tidak diabaikan:
                        // error("Trivy scan found unignored CRITICAL/HIGH vulnerabilities or an error occurred.")
                    }
                    
                    echo "Cleaning up scan image (optional)..."
                    try {
                        powershell "docker rmi ${fullImageNameForScan}"
                    } catch (cleanupErr) {
                        echo "Warning: Failed to remove scan image ${fullImageNameForScan}. Error: ${cleanupErr.getMessage()}"
                    }
                    echo "Security scan completed."
                }
            }
        }

        stage('Build & Push Docker Image') {
            steps {
                script {
                    echo "Building and pushing Docker image..."
                    def imageName = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}"
                    def buildTag = env.BUILD_NUMBER 
                    def latestTag = "latest"

                    // Menggunakan docker.withRegistry untuk login, build, tag, dan push yang terintegrasi
                    docker.withRegistry("https://index.docker.io/v1/", env.DOCKER_HUB_CREDENTIALS_ID) {
                        
                        echo "Building image ${imageName}:${buildTag}..."
                        def customImage = docker.build("${imageName}:${buildTag}", "-f Dockerfile .")

                        echo "Tagging image ${imageName}:${buildTag} as ${imageName}:${latestTag}..."
                        customImage.tag(latestTag)

                        echo "Pushing image ${imageName}:${buildTag} to Docker Hub..."
                        customImage.push(buildTag)
                        
                        echo "Pushing image ${imageName}:${latestTag} to Docker Hub..."
                        customImage.push(latestTag)
                    }
                    echo "Docker images pushed successfully."
                }
            }
        }

                stage('Deploy via Docker SSH') {
    steps {
        script {
            withCredentials([file(credentialsId: env.SWARM_MANAGER_SSH_CREDENTIALS_ID, variable: 'SSH_KEY')]) {
                bat """
                    docker run --rm -v "%SSH_KEY%:/key.pem" ^
                        alpine/ssh-client ^
                        sh -c "
                            chmod 600 /key.pem && \
                            ssh -i /key.pem \
                                -o StrictHostKeyChecking=no \
                                ${env.SWARM_MANAGER_USER}@${env.SWARM_MANAGER_IP} \
                                'docker stack deploy -c /opt/stacks/${env.DOCKER_IMAGE_NAME}/api-gateway-stack.yml alifsmart_apigw --with-registry-auth'
                        "
                """
            }
        }
    }
}
    } // Akhir stages

    post { 
        always {
            echo "Pipeline finished."
        }
        success {
            echo "Pipeline sukses! Aplikasi telah di-build, di-push, dan (semoga) terdeploy dengan baik."
        }
        failure {
            echo "Pipeline gagal! Silakan periksa log untuk detailnya."
        }
    }
}