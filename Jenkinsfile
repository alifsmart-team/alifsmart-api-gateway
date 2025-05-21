// Jenkinsfile
pipeline {
    agent any // Pastikan agent ini memiliki Docker & Git terinstal dan dikonfigurasi dengan benar

    tools {
        git 'Default'
    }

    environment {
        // ... (environment variables lainnya tetap sama) ...
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME   = 'alifsmart-api-gateway'
        FULL_APP_IMAGE_NAME = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
        ENV_REDIS_HOST            = credentials('redis_host')
        ENV_REDIS_PORT            = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED   = credentials('redis_tls_is_enabled')
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id'
        SWARM_MANAGER_IP                 = '47.84.46.116'
        SWARM_MANAGER_USER               = 'root'
        REMOTE_APP_DIR                   = '/opt/stacks/alifsmart-api-gateway'
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'
        GITHUB_CREDENTIALS_ID = 'github_pat'
        
        // Menentukan versi Trivy yang akan digunakan
        TRIVY_VERSION = '0.55.0' // Ganti dengan versi spesifik yang Anda inginkan
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Checking out from GitHub repository..."
                git branch: 'main',
                    credentialsId: env.GITHUB_CREDENTIALS_ID,
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git'
                echo "Checkout complete."
            }
        }

        stage('Install Dependencies & Test') {
            steps {
                echo "Installing dependencies and running tests inside Docker..."
                sh """
                    docker run --rm \\
                        -v "${env.WORKSPACE}:/app" \\
                        -w /app \\
                        -e ENV_REDIS_HOST=${env.ENV_REDIS_HOST} \\
                        -e ENV_REDIS_PORT=${env.ENV_REDIS_PORT} \\
                        -e ENV_REDIS_TLS_ENABLED=${env.ENV_REDIS_TLS_ENABLED} \\
                        node:18-alpine sh -c 'echo "Cleaning npm cache..." && npm cache clean --force && echo "Running npm ci and tests..." && npm ci && npm run test -- --passWithNoTests'
                """
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy version ${env.TRIVY_VERSION}..."
                    def fullImageNameForScan = "${env.FULL_APP_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"

                    echo "Building temporary image for scan (with --no-cache): ${fullImageNameForScan}"
                    docker.build(fullImageNameForScan, "--no-cache -f Dockerfile .")
                    
                    echo "Ensuring Trivy image ${env.TRIVY_VERSION} is available..."
                    // Opsional: Tarik image Trivy versi spesifik jika belum ada atau untuk memastikan
                    // sh "docker pull aquasec/trivy:${env.TRIVY_VERSION}" 
                    // Biasanya, Docker akan menariknya secara otomatis jika belum ada saat 'docker run'.


                    echo "Cleaning persistent Trivy cache volume using Trivy ${env.TRIVY_VERSION}..."
                        sh """
                            docker run --rm \\
                                -v trivycache:/root/.cache/ \\
                                aquasec/trivy:${env.TRIVY_VERSION} clean 
                        """ // <-- Removed --all from here
                    echo "Persistent Trivy cache volume 'trivycache' cleaned."

                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities with Trivy ${env.TRIVY_VERSION} (without using persistent cache for the scan itself)..."
                    try {
                        sh """
                            docker run --rm \\
                                -v /var/run/docker.sock:/var/run/docker.sock \\
                                -v "${env.WORKSPACE}:/scan_ws" \\
                                -w /scan_ws \\
                                aquasec/trivy:${env.TRIVY_VERSION} image \\
                                --exit-code 1 \\
                                --severity CRITICAL,HIGH \\
                                --ignore-unfixed \\
                                --ignore-ids CVE-2024-21538 \\
                                ${fullImageNameForScan}
                        """
                        // Jika Anda memutuskan untuk menggunakan .trivyignore secara eksklusif,
                        // hapus baris --ignore-ids CVE-2024-21538 di atas.
                        echo "Trivy scan passed or specified vulnerabilities were ignored."
                    } catch (err) {
                        echo "Trivy scan failed or found unignored CRITICAL/HIGH vulnerabilities. Error: ${err.getMessage()}"
                        error("Trivy scan found unignored CRITICAL/HIGH vulnerabilities or an error occurred.")
                    } finally {
                        echo "Cleaning up scan image (optional)..."
                        try {
                            sh "docker rmi ${fullImageNameForScan} || true"
                        } catch (cleanupErr) {
                            echo "Warning: Failed to remove scan image ${fullImageNameForScan}. Error: ${cleanupErr.getMessage()}"
                        }
                    }
                    echo "Security scan completed."
                }
            }
        }

        // ... (stage 'Build & Push Docker Image' dan 'Deploy via Docker SSH' tetap sama) ...
        // Pastikan untuk memperbarui panggilan ke Trivy di tempat lain jika ada.

        stage('Build & Push Docker Image') {
            steps {
                script {
                    echo "Building and pushing Docker image..."
                    def buildTag = env.BUILD_NUMBER 
                    def latestTag = "latest"

                    docker.withRegistry("https://index.docker.io/v1/", env.DOCKER_HUB_CREDENTIALS_ID) {
                        
                        echo "Building image ${env.FULL_APP_IMAGE_NAME}:${buildTag}..."
                        def customImage = docker.build("${env.FULL_APP_IMAGE_NAME}:${buildTag}", "-f Dockerfile .")

                        echo "Tagging image ${env.FULL_APP_IMAGE_NAME}:${buildTag} as ${env.FULL_APP_IMAGE_NAME}:${latestTag}..."
                        customImage.tag(latestTag) 

                        echo "Pushing image ${env.FULL_APP_IMAGE_NAME}:${buildTag} to Docker Hub..."
                        customImage.push(buildTag)
                        
                        echo "Pushing image ${env.FULL_APP_IMAGE_NAME}:${latestTag} to Docker Hub..."
                        customImage.push(latestTag)
                    }
                    echo "Docker images pushed successfully."
                }
            }
        }

        stage('Deploy via Docker SSH') {
            steps {
                script {
                    withCredentials([sshUserPrivateKey(credentialsId: env.SWARM_MANAGER_SSH_CREDENTIALS_ID, keyFileVariable: 'SSH_PRIVATE_KEY_FILE')]) {
                        def remoteHost = "${env.SWARM_MANAGER_USER}@${env.SWARM_MANAGER_IP}"
                        
                        echo "Target remote login: ${remoteHost}"
                        echo "Creating remote directory (if not exists): ${env.REMOTE_APP_DIR}"
                        sh """
                            ssh -i \${SSH_PRIVATE_KEY_FILE} \\
                                -o StrictHostKeyChecking=no \\
                                -o UserKnownHostsFile=/dev/null \\
                                ${remoteHost} 'mkdir -p ${env.REMOTE_APP_DIR}'
                        """

                        echo "Deploying application on remote server: ${env.FULL_APP_IMAGE_NAME}:latest"
                        sh """
                            ssh -i \${SSH_PRIVATE_KEY_FILE} \\
                                -o StrictHostKeyChecking=no \\
                                -o UserKnownHostsFile=/dev/null \\
                                ${remoteHost} "cd ${env.REMOTE_APP_DIR} && \\
                                    echo 'Pulling latest image...' && \\
                                    docker pull ${env.FULL_APP_IMAGE_NAME}:latest && \\
                                    echo 'Stopping and removing old container (if any)...' && \\
                                    docker stop alifsmart-api-gateway-container || true && \\
                                    docker rm alifsmart-api-gateway-container || true && \\
                                    echo 'Starting new container...' && \\
                                    docker run -d --name alifsmart-api-gateway-container \\
                                        -p 8080:3000 \\
                                        -e ENV_REDIS_HOST=${env.ENV_REDIS_HOST} \\
                                        -e ENV_REDIS_PORT=${env.ENV_REDIS_PORT} \\
                                        -e ENV_REDIS_TLS_ENABLED=${env.ENV_REDIS_TLS_ENABLED} \\
                                        --restart unless-stopped \\
                                        ${env.FULL_APP_IMAGE_NAME}:latest"
                        """
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