// Jenkinsfile
pipeline {
    agent any // Pastikan agent ini memiliki Docker & Git terinstal dan dikonfigurasi dengan benar

    tools {
        git 'Default'
    }

    environment {
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME   = 'alifsmart-api-gateway'
        FULL_APP_IMAGE_NAME = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
        ENV_REDIS_HOST            = credentials('redis_host')
        ENV_REDIS_PORT            = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED   = credentials('redis_tls_is_enabled')
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id'
        SWARM_MANAGER_IP               = '47.84.46.116'
        SWARM_MANAGER_USER             = 'root'
        REMOTE_APP_DIR                 = '/opt/stacks/alifsmart-api-gateway'
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'
        GITHUB_CREDENTIALS_ID = 'github_pat'
        TRIVY_VERSION = '0.55.0' // Pastikan versi Trivy ini sesuai dengan kebutuhan Anda
        
        // Menentukan versi Node.js yang akan digunakan
        NODE_VERSION_ALPINE = 'node:20-alpine'
    }

    stages {
        stage('Checkout') {
            steps {
                cleanWs()
                echo "Checking out from GitHub repository..."
                git branch: 'main',
                    credentialsId: env.GITHUB_CREDENTIALS_ID,
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git'
                echo "Checkout complete."
            }
        }

        stage('Install Dependencies & Test') {
            steps {
                echo "Installing dependencies and running tests inside Docker using ${env.NODE_VERSION_ALPINE}..."
                sh """
                    docker run --rm \\
                        -v "${env.WORKSPACE}:/app" \\
                        -w /app \\
                        -e ENV_REDIS_HOST=${env.ENV_REDIS_HOST} \\
                        -e ENV_REDIS_PORT=${env.ENV_REDIS_PORT} \\
                        -e ENV_REDIS_TLS_ENABLED=${env.ENV_REDIS_TLS_ENABLED} \\
                        ${env.NODE_VERSION_ALPINE} sh -c 'echo "Cleaning npm cache..." && npm cache clean --force && echo "Running npm ci and tests..." && npm ci && npm run test -- --passWithNoTests'
                """
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Build & Push Docker Image') {
            steps {
                script {
                    echo "Building and pushing Docker image (using Node 20 from Dockerfile)..."
                    def buildTag = env.BUILD_NUMBER 
                    def latestTag = "latest"

                    docker.withRegistry("https://index.docker.io/v1/", env.DOCKER_HUB_CREDENTIALS_ID) {
                        // Dockerfile sekarang akan menggunakan FROM node:20-alpine
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

        // --- TAHAP BARU UNTUK SCAN TRIVY ---
        stage('Scan with Trivy') {
            steps {
                script {
                    echo "Scanning Docker image ${env.FULL_APP_IMAGE_NAME}:${env.BUILD_NUMBER} with Trivy..."
                    // Tarik image yang baru saja di-push untuk memastikan kita memindai versi yang benar
                    // Jika agent Jenkins dan Docker daemon berada di host yang sama,
                    // image mungkin sudah tersedia secara lokal setelah build.
                    // Namun, pull eksplisit memastikan image terbaru dari registry yang digunakan.
                    docker.withRegistry("https://index.docker.io/v1/", env.DOCKER_HUB_CREDENTIALS_ID) {
                        sh "docker pull ${env.FULL_APP_IMAGE_NAME}:${env.BUILD_NUMBER}"
                    }

                    // Jalankan Trivy menggunakan image Docker resmi Trivy
                    // --rm akan menghapus kontainer setelah selesai
                    // -v /var/run/docker.sock:/var/run/docker.sock memungkinkan Trivy mengakses Docker daemon
                    // -v $HOME/trivy-cache:/root/.cache/trivy cache direktori untuk mempercepat scan berikutnya
                    // --exit-code 1 akan membuat build gagal jika ada kerentanan HIGH atau CRITICAL
                    // --severity HIGH,CRITICAL hanya melaporkan kerentanan dengan tingkat keparahan tersebut
                    // --format table untuk output yang mudah dibaca di log Jenkins
                    // Ganti ${env.FULL_APP_IMAGE_NAME}:${env.BUILD_NUMBER} dengan image yang ingin Anda pindai
                    try {
                        sh """
                            docker run --rm \\
                                -v /var/run/docker.sock:/var/run/docker.sock \\
                                -v \$HOME/.trivycache:/root/.cache/trivy \\
                                aquasec/trivy:${env.TRIVY_VERSION} image \\
                                --exit-code 1 \\
                                --severity HIGH,CRITICAL \\
                                --ignore-unfixed \\
                                --format table \\
                                ${env.FULL_APP_IMAGE_NAME}:${env.BUILD_NUMBER}
                        """
                        // Anda bisa menambahkan opsi --output trivy-report.json untuk menyimpan hasil scan
                        // dan kemudian mengarsipkannya menggunakan archiveArtifacts
                        // contoh: aquasec/trivy:${env.TRIVY_VERSION} image --format json --output trivy-results.json ${env.FULL_APP_IMAGE_NAME}:${env.BUILD_NUMBER}
                        // archiveArtifacts artifacts: 'trivy-results.json', fingerprint: true
                    } catch (e) {
                        // Tangani error jika Trivy menemukan kerentanan (karena --exit-code 1)
                        echo "Trivy scan found vulnerabilities or an error occurred."
                        // currentBuild.result = 'FAILURE' // Sudah diatur oleh exit code 1
                        throw e // Lempar kembali error untuk menghentikan pipeline
                    }
                    echo "Trivy scan completed."
                }
            }
        }
        // --- AKHIR TAHAP SCAN TRIVY ---

        stage('Deploy via Docker SSH') {
            when {
                // Hanya deploy jika branch adalah main dan build sebelumnya (termasuk scan) sukses
                branch 'main' 
                // Anda bisa juga menambahkan pengecekan status build sebelumnya jika perlu
                // expression { currentBuild.result == null || currentBuild.result == 'SUCCESS' }
            }
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
            // Bersihkan workspace
            cleanWs()
        }
        success {
            echo "Pipeline sukses! Aplikasi telah di-build, di-scan, di-push, dan (semoga) terdeploy dengan baik."
        }
        failure {
            echo "Pipeline gagal! Silakan periksa log untuk detailnya."
        }
    }
}