// Jenkinsfile
pipeline {
    agent any // Pastikan agent ini memiliki Docker & Git

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

        // OPSIONAL: Jika sumber daya memungkinkan, aktifkan kembali tahap Test & Scan
        /* stage('Install Dependencies & Test') { ... }
        stage('Security Scan (Trivy)') { ... }
        */

        stage('Build & Push Docker Image') {
            steps {
                script {
                    echo "Building and pushing Docker image..."
                    def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
                    def imageWithBuildTag = "${imageBaseName}:${env.BUILD_ID}"
                    def imageWithLatestTag = "${imageBaseName}:latest"

                    echo "Logging in to Docker Hub as ${DOCKER_HUB_USERNAME}..."
                    // Gunakan docker.withRegistry untuk login yang lebih aman dan terintegrasi
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
                        def stackFileNameOnRepo = "api-gateway-stack.yml" // File dari repo Anda
                        def stackNameInSwarm = "alifsmart_stack" // Nama stack di Swarm

                        sh "ssh -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${remoteLogin} \"mkdir -p ${remoteStackPath}\""
                        sh "scp -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ./${stackFileNameOnRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameOnRepo}"

                        // Variabel environment dari Jenkins akan disubstitusi di dalam stack file oleh Docker Swarm
                        // jika stack file Anda menggunakan format ${VARIABLE} atau $VARIABLE
                        // Perintah export di bawah adalah untuk memastikan variabel tersebut ada di environment shell remote
                        // saat docker stack deploy dijalankan.
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

    post { // Aksi setelah semua stage selesai
        always {
            echo "Pipeline finished."
            // cleanWs() // Bersihkan workspace jika perlu
        }
        success {
            echo "Pipeline sukses!"
            // Kirim notifikasi sukses
        }
        failure {
            echo "Pipeline gagal!"
            // Kirim notifikasi gagal
        }
    }
}