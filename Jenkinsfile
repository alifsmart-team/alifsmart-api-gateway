// Jenkinsfile
pipeline {
    agent any // Pastikan agent ini memiliki Docker & Git terinstal dan dikonfigurasi dengan benar

    tools {
        // Nama instalasi Git dari Manage Jenkins > Tools
        // Jika Git sudah ada di PATH agent, ini mungkin tidak selalu diperlukan.
        git 'Default'
    }

    environment {
        // Konfigurasi Docker Image
        DOCKER_HUB_USERNAME = 'vitoackerman' // Username Docker Hub Anda
        DOCKER_IMAGE_NAME   = 'alifsmart-api-gateway' // Nama image aplikasi Anda
        // Nama image lengkap untuk aplikasi (digunakan saat push dan deploy)
        FULL_APP_IMAGE_NAME = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}" // Dihasilkan dari variabel di atas

        // ID Kredensial Redis dari Jenkins (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        // Ini akan memuat konten kredensial ke dalam variabel lingkungan.
        ENV_REDIS_HOST            = credentials('redis_host')
        ENV_REDIS_PORT            = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED   = credentials('redis_tls_is_enabled') // Pastikan nilai kredensial ini adalah string 'true' atau 'false'

        // Detail Swarm Manager & ID Kredensial SSH
        // SWARM_MANAGER_SSH_CREDENTIALS_ID menyimpan ID dari Jenkins Credential yang akan digunakan.
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id' // ID Jenkins Credential Anda yang berisi private key
        SWARM_MANAGER_IP                 = '47.84.46.116'
        SWARM_MANAGER_USER               = 'root' // Hati-hati menggunakan user root
        REMOTE_APP_DIR                   = '/opt/stacks/alifsmart-api-gateway' // Direktori aplikasi di server remote
        
        // ID Kredensial Docker Hub (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        // Digunakan oleh docker.withRegistry() dan docker.build().push()
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'

        // ID Kredensial GitHub PAT (GANTI DENGAN ID YANG BENAR DARI JENKINS ANDA)
        GITHUB_CREDENTIALS_ID = 'github_pat'
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Checking out from GitHub repository..."
                git branch: 'main', // Ganti dengan branch yang Anda inginkan
                    credentialsId: env.GITHUB_CREDENTIALS_ID, // Menggunakan variabel environment
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git'
                echo "Checkout complete."
            }
        }

        stage('Install Dependencies & Test') {
            steps {
                echo "Installing dependencies and running tests inside Docker..."
                // Menggunakan sh untuk menjalankan di agent Linux
                // Variabel Redis dari environment Jenkins akan otomatis tersedia di dalam sh block ini.
                // Kita perlu meneruskannya secara eksplisit ke dalam container Docker.
                sh """
                    docker run --rm \\
                        -v "${env.WORKSPACE}:/app" \\
                        -w /app \\
                        -e ENV_REDIS_HOST=${env.ENV_REDIS_HOST} \\
                        -e ENV_REDIS_PORT=${env.ENV_REDIS_PORT} \\
                        -e ENV_REDIS_TLS_ENABLED=${env.ENV_REDIS_TLS_ENABLED} \\
                        node:18-alpine sh -c 'npm ci && npm run test -- --passWithNoTests'
                """
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') {
    steps {
        script {
            echo "Starting security scan with Trivy..."
            def fullImageNameForScan = "${env.FULL_APP_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"

            echo "Building temporary image for scan: ${fullImageNameForScan}"
            docker.build(fullImageNameForScan, "-f Dockerfile .")
            
            echo "Cleaning persistent Trivy cache volume (if used elsewhere or for general hygiene)..."
            // Langkah ini membersihkan named volume 'trivycache'.
            // Ini mungkin tidak berdampak langsung ke scan di bawah jika scan tidak me-mount volume ini,
            // tapi baik untuk menjaga kebersihan volume 'trivycache' jika ada.
            sh """
                docker run --rm \\
                    -v trivycache:/root/.cache/ \\
                    aquasec/trivy:latest clean --all
            """
            echo "Persistent Trivy cache volume 'trivycache' cleaned."

            echo "Scanning image ${fullImageNameForScan} for vulnerabilities (without using persistent cache for the scan itself)..."
            try {
                // Perintah scan sekarang TIDAK me-mount volume 'trivycache'.
                // Trivy akan mengunduh DB ke cache internal kontainer yang bersifat sementara.
                sh """
                    docker run --rm \\
                        -v /var/run/docker.sock:/var/run/docker.sock \\
                        -v "${env.WORKSPACE}:/scan_ws" \\
                        -w /scan_ws \\
                        aquasec/trivy:latest image \\
                        --exit-code 1 \\
                        --severity CRITICAL,HIGH \\
                        --ignore-unfixed \\
                        --ignore-ids CVE-2024-21538 \\
                        ${fullImageNameForScan}
                """
                echo "Trivy scan passed or ignored vulnerabilities did not cause failure."
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
                        customImage.tag(latestTag) // Menambahkan tag 'latest' ke image yang sama

                        echo "Pushing image ${env.FULL_APP_IMAGE_NAME}:${buildTag} to Docker Hub..."
                        customImage.push(buildTag)
                        
                        echo "Pushing image ${env.FULL_APP_IMAGE_NAME}:${latestTag} to Docker Hub..."
                        customImage.push(latestTag) // Push tag 'latest'
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