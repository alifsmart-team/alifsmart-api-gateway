// Jenkinsfile
pipeline {
    agent any // Pastikan agent ini memiliki Docker & Git terinstal dan dikonfigurasi dengan benar

    tools {
        git 'Default' // Nama Git tool dari Manage Jenkins > Tools
    }

    environment {
        // Konfigurasi Docker Image
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'

        // ID Kredensial Redis dari Jenkins
        ENV_REDIS_HOST = credentials('redis_host') // Sesuaikan ID!
        ENV_REDIS_PORT = credentials('redis_port') // Sesuaikan ID!
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled') // Sesuaikan ID!

        // Detail Swarm Manager & ID Kredensial SSH
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id' // Sesuaikan ID!
        SWARM_MANAGER_IP = '47.84.46.116' // IP Server 1 Anda

        // ID Kredensial Docker Hub
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id' // Sesuaikan ID!

        // ID Kredensial GitHub
        GITHUB_CREDENTIALS_ID = 'github_pat' // Sesuaikan ID!
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

        stage('Install Dependencies & Test') { // <--- TAHAP INI DIAKTIFKAN KEMBALI
            steps {
                echo "Installing dependencies and running tests..."
                // 'npm ci' lebih disarankan untuk CI/CD karena install dependencies persis dari package-lock.json
                // dan biasanya lebih cepat. 'npm ci' juga akan menginstall devDependencies.
                // Pastikan agent Jenkins (mesin lokal Anda) memiliki Docker terinstal dan bisa menjalankan container.
                sh 'docker run --rm -v $(pwd):/app -w /app node:18-alpine sh -c "npm ci && npm test"'
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') { // <--- TAHAP INI DIAKTIFKAN KEMBALI
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    // Pastikan Trivy terinstall di agent atau bisa dijalankan via Docker
                    // Jika Trivy tidak terinstal di agent, Anda bisa menjalankannya via Docker.
                    // Contoh di bawah menggunakan Trivy yang ada di PATH. Jika via Docker, sesuaikan perintah sh.

                    def fullImageNameForScan = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:scan-${env.BUILD_ID}"
                    
                    echo "Building temporary image for scan: ${fullImageNameForScan}"
                    // Asumsikan Dockerfile ada di root workspace
                    sh "docker build -f Dockerfile -t ${fullImageNameForScan} ."
                    
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities..."
                    // Gagal_kan pipeline jika ada vulnerability CRITICAL atau HIGH
                    // Jika trivy tidak ada di PATH, ganti dengan perintah docker run untuk trivy, contoh:
                    // sh "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v \$(pwd)/.trivycache:/root/.cache/ aquasec/trivy:latest image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed ${fullImageNameForScan}"
                    sh "trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed ${fullImageNameForScan}"
                    echo "Security scan completed."
                }
            }
        }

        stage('Build & Push Docker Image') {
            steps {
                script {
                    echo "Building and pushing Docker image..."
                    def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
                    def imageWithBuildTag = "${imageBaseName}:${env.BUILD_ID}"
                    def imageWithLatestTag = "${imageBaseName}:latest"

                    echo "Logging in to Docker Hub as ${DOCKER_HUB_USERNAME}..."
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_HUB_CREDENTIALS_ID) {
                        echo "Building image ${imageWithBuildTag}..."
                        def customImage = docker.build("${imageWithBuildTag}", "-f Dockerfile .")

                        echo "Tagging image ${imageWithBuildTag} as ${imageWithLatestTag}..."
                        customImage.tag(imageWithLatestTag)

                        echo "Pushing image ${imageWithBuildTag} to Docker Hub..."
                        customImage.push() // Mendorong tag dengan BUILD_ID
                        echo "Pushing image ${imageWithLatestTag} to Docker Hub..."
                        customImage.push(imageWithLatestTag) // Mendorong tag 'latest'
                    }
                    echo "Docker images pushed and logout successful."
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
                        def stackNameInSwarm = "alifsmart_stack" 

                        sh "ssh -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${remoteLogin} \"mkdir -p ${remoteStackPath}\""
                        sh "scp -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ./${stackFileNameOnRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameOnRepo}"
                        
                        sh """
                        ssh -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${remoteLogin} \\
                            "export DOCKER_HUB_USERNAME='${DOCKER_HUB_USERNAME}' && \\
                             export DOCKER_IMAGE_NAME='${DOCKER_IMAGE_NAME}' && \\
                             export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}' && \\
                             export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}' && \\
                             export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}' && \\
                             echo 'Deploying stack ${stackNameInSwarm}...' && \\
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
    } // Akhir stages

    post { 
        always {
            echo "Pipeline finished."
            // cleanWs() 
        }
        success {
            echo "Pipeline sukses!"
        }
        failure {
            echo "Pipeline gagal!"
        }
    }
}