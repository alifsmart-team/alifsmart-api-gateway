// Jenkinsfile
pipeline {
    agent any // Atau tentukan agent spesifik yang memiliki Docker dan Git terinstal

    tools {
        git 'Default'
    }

    environment {
        // Konfigurasi Docker Image
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'

        // Kredensial untuk Redis
        ENV_REDIS_HOST = credentials('f80778c6-6904-49cf-8b86-e909905fe4ac')
        ENV_REDIS_PORT = credentials('460e1099-ca40-4918-8d90-7415c4b94b31')
        ENV_REDIS_TLS_ENABLED = credentials('870dd061-f6ba-49dc-8e22-450af5e1d528')

        // Kredensial SSH untuk Docker Swarm Manager
        SWARM_MANAGER_SSH_CREDENTIALS_ID = '0c68d9d8-670b-497f-9106-031cdd2a6eb5'
        SWARM_MANAGER_IP = '47.84.46.116'
        
        // Kredensial Docker Hub
        DOCKER_HUB_CREDENTIALS_ID = 'bb4fa84d-a3b2-40a0-8a7e-b7d566d795d7'

        // Kredensial GitHub
        GITHUB_CREDENTIALS_ID = 'cb5e191b-7046-4d8d-a146-25148ed7d6a4'
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Checking out from GitHub repository: https://github.com/alifsmart-team/alifsmart-api-gateway.git on branch main"
                git branch: 'main',
                    credentialsId: env.GITHUB_CREDENTIALS_ID,
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git'
                echo "Checkout complete."
            }
        }

        /* // TAHAP INI DIHAPUS/DIKOMENTARI KARENA KETERBATASAN SUMBER DAYA
        stage('Install Dependencies & Test') {
            steps {
                echo "Installing dependencies and running tests..."
                sh 'docker run --rm -v $(pwd):/app -w /app node:18-alpine sh -c "npm ci && npm test"'
                echo "Dependencies installed and tests completed."
            }
        }
        */

        /* // TAHAP INI DIHAPUS/DIKOMENTARI KARENA KETERBATASAN SUMBER DAYA
        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    def fullImageNameForScan = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:scan-${env.BUILD_ID}"
                    echo "Building temporary image for scan: ${fullImageNameForScan}"
                    sh "docker build -f Dockerfile -t ${fullImageNameForScan} ."
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities..."
                    sh "trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed ${fullImageNameForScan}"
                    echo "Security scan completed."
                }
            }
        }
        */

        stage('Build & Push Docker Image') {
            steps {
                script {
                    echo "Building and pushing Docker image..."
                    def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
                    def imageWithBuildTag = "${imageBaseName}:${env.BUILD_ID}"
                    def imageWithLatestTag = "${imageBaseName}:latest"

                    echo "Logging in to Docker Hub as ${DOCKER_HUB_USERNAME}..."
                    withCredentials([usernamePassword(credentialsId: DOCKER_HUB_CREDENTIALS_ID, usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                        sh "echo \"${DOCKER_PASS}\" | docker login -u \"${DOCKER_USER}\" --password-stdin docker.io"
                    }
                    echo "Docker login successful."
                    
                    echo "Building image ${imageWithBuildTag}..."
                    // Pastikan Dockerfile Anda melakukan instalasi dependensi dengan benar (misal, menjalankan npm ci atau npm install)
                    sh "docker build -f Dockerfile -t ${imageWithBuildTag} ."
                    echo "Tagging image ${imageWithBuildTag} as ${imageWithLatestTag}..."
                    sh "docker tag ${imageWithBuildTag} ${imageWithLatestTag}"
                    
                    echo "Pushing image ${imageWithBuildTag} to Docker Hub..."
                    sh "docker push ${imageWithBuildTag}"
                    echo "Pushing image ${imageWithLatestTag} to Docker Hub..."
                    sh "docker push ${imageWithLatestTag}"
                    echo "Docker images pushed."
                }
            }
        }

        stage('Deploy to Docker Swarm') {
            steps {
                echo "Preparing to deploy to Docker Swarm..."
                withCredentials([sshUserPrivateKey(
                    credentialsId: SWARM_MANAGER_SSH_CREDENTIALS_ID,
                    keyFileVariable: 'SSH_PRIVATE_KEY_FILE',
                    usernameVariable: 'SSH_USERNAME'
                )]) {
                    script {
                        def remoteLogin = "${env.SSH_USERNAME}@${SWARM_MANAGER_IP}"
                        def remoteStackPath = "/opt/stacks/alifsmart-api-gateway"
                        def stackFileNameOnRepo = "api-gateway-stack.yml"
                        def stackNameInSwarm = "alifsmart_apigw"

                        echo "Preparing remote directory ${remoteStackPath} on ${remoteLogin}..."
                        sh "ssh -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${remoteLogin} \"mkdir -p ${remoteStackPath}\""
                        
                        echo "Copying ${stackFileNameOnRepo} to ${remoteLogin}:${remoteStackPath}/${stackFileNameOnRepo}..."
                        sh "scp -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ./${stackFileNameOnRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameOnRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        sh """
                        ssh -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${remoteLogin} \\
                            "export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}' && \\
                             export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}' && \\
                             export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}' && \\
                             echo 'Attempting to deploy stack ${stackNameInSwarm} using image ${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:latest...' && \\
                             docker stack deploy \\
                                -c ${remoteStackPath}/${stackFileNameOnRepo} \\
                                ${stackNameInSwarm} \\
                                --with-registry-auth"
                        """
                        echo "Deployment to Docker Swarm initiated."
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                echo "Pipeline finished. Starting cleanup (optional)..."
                // ... (logika cleanup jika ada) ...
                echo "Cleanup process finished."
            }
        }
        success {
            echo "Pipeline sukses! API Gateway udah diupdate dan (semoga) terdeploy dengan selamat."
        }
        failure {
            echo "Waduh, pipeline gagal nih, bos! Cek lognya buruan, ada yang gak beres."
        }
    }
}