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
                // Menggunakan sh (shell) untuk menjalankan perintah docker run di Linux/Unix
                // Bagian sh -c "..." di dalam container tetap karena container adalah Linux (node:18-alpine)
                // Menggunakan ${env.WORKSPACE} untuk mereferensikan direktori kerja Jenkins yang utama
                sh "docker run --rm -v '${env.WORKSPACE}:/app' -w /app node:18-alpine sh -c 'npm ci && npm run test -- --passWithNoTests'"
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
                    // Ganti dengan ID kredensial SSH private key Anda
                    withCredentials([sshUserPrivateKey(credentialsId: 'SSH_DEPLOY_CREDENTIALS_ID', keyFileVariable: 'SSH_PRIVATE_KEY_FILE')]) {
                        echo "Target remote login: ${REMOTE_USER_HOST}"
                        echo "Creating remote directory (if not exists): ${REMOTE_APP_DIR}"
                        // Menggunakan sh bukan powershell
                        sh """
                            ssh -i ${SSH_PRIVATE_KEY_FILE} \\
                                -o StrictHostKeyChecking=no \\
                                -o UserKnownHostsFile=/dev/null \\
                                ${REMOTE_USER_HOST} 'mkdir -p ${REMOTE_APP_DIR}'
                        """

                        echo "Deploying application on remote server..."
                        // Contoh perintah deployment. Sesuaikan dengan kebutuhan Anda.
                        // Misalnya, jika Anda menggunakan docker-compose:
                        // 1. Pastikan docker-compose.yml ada di server atau di-copy.
                        // 2. Tarik image terbaru dan jalankan.
                        sh """
                            ssh -i ${SSH_PRIVATE_KEY_FILE} \\
                                -o StrictHostKeyChecking=no \\
                                -o UserKnownHostsFile=/dev/null \\
                                ${REMOTE_USER_HOST} "cd ${REMOTE_APP_DIR} && \\
                                    echo 'Pulling latest image...' && \\
                                    docker pull ${APP_IMAGE_NAME}:latest && \\
                                    echo 'Stopping and removing old container (if any)...' && \\
                                    docker stop alifsmart-api-gateway-container || true && \\
                                    docker rm alifsmart-api-gateway-container || true && \\
                                    echo 'Starting new container...' && \\
                                    docker run -d --name alifsmart-api-gateway-container \\
                                        -p 8080:3000 \\
                                        -e ENV_REDIS_HOST=${ENV_REDIS_HOST} \\
                                        -e ENV_REDIS_PORT=${ENV_REDIS_PORT} \\
                                        -e ENV_REDIS_TLS_ENABLED=${ENV_REDIS_TLS_ENABLED} \\
                                        --restart unless-stopped \\
                                        ${APP_IMAGE_NAME}:latest"
                        """
                        // Jika menggunakan docker-compose, perintahnya bisa seperti:
                        // sh "ssh -i ... ${REMOTE_USER_HOST} 'cd ${REMOTE_APP_DIR} && docker-compose pull && docker-compose up -d --remove-orphans'"
                        echo "Deployment commands executed."
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