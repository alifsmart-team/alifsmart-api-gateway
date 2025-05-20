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

        // ID Kredensial Redis dari Jenkins (Ganti dengan ID yang benar)
        ENV_REDIS_HOST = credentials('redis_host')
        ENV_REDIS_PORT = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled')

        // Detail Swarm Manager & ID Kredensial SSH (Ganti dengan ID yang benar)
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id'
        SWARM_MANAGER_IP = '47.84.46.116' // IP Server 1 Swarm Manager Anda
        
        // ID Kredensial Docker Hub (Ganti dengan ID yang benar)
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'

        // ID Kredensial GitHub PAT (Ganti dengan ID yang benar)
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
                // Menggunakan Docker untuk menjalankan tes di lingkungan yang bersih dan terisolasi
                // Pastikan image node:18-alpine bisa di-pull oleh Docker daemon Anda
                sh 'docker run --rm -v "$(pwd)":/app -w /app node:18-alpine sh -c "npm ci && npm test"'
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    def fullImageNameForScan = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:scan-${env.BUILD_NUMBER}" // Menggunakan BUILD_NUMBER untuk tag unik

                    echo "Building temporary image for scan: ${fullImageNameForScan}"
                    // Menggunakan plugin Docker Pipeline untuk build
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_HUB_CREDENTIALS_ID) { // Login mungkin diperlukan jika base image privat
                        def scanImage = docker.build(fullImageNameForScan, "-f Dockerfile .") // Asumsikan Dockerfile ada di root
                        // Tidak perlu push image scan ini ke registry
                    }
                    
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities..."
                    // Asumsikan 'trivy' ada di PATH agent Jenkins.
                    // Jika tidak, jalankan Trivy via Docker:
                    // sh "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed ${fullImageNameForScan}"
                    sh "trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed ${fullImageNameForScan}"
                    
                    // Bersihkan image scan setelah selesai (opsional, tapi baik untuk menghemat ruang)
                    // Gunakan try-catch agar tidak menggagalkan pipeline jika rmi gagal (misal, image sedang digunakan)
                    try {
                        sh "docker rmi ${fullImageNameForScan}"
                    } catch (err) {
                        echo "Warning: Failed to remove scan image ${fullImageNameForScan}. Error: ${err.getMessage()}"
                    }
                    echo "Security scan completed."
                }
            }
        }

        stage('Build & Push Docker Image') {
            steps {
                script {
                    echo "Building and pushing Docker image..."
                    def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
                    // Menggunakan env.BUILD_NUMBER untuk tag yang unik per build
                    def imageWithBuildTag = "${imageBaseName}:${env.BUILD_NUMBER}"
                    def imageWithLatestTag = "${imageBaseName}:latest"

                    // Menggunakan docker.withRegistry untuk login, build, tag, dan push yang terintegrasi
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_HUB_CREDENTIALS_ID) {
                        echo "Building image ${imageWithBuildTag}..."
                        // Opsi '-f Dockerfile .' menentukan Dockerfile dan konteks build.
                        // Konteks '.' berarti direktori workspace Jenkins saat ini.
                        def customImage = docker.build(imageWithBuildTag, "-f Dockerfile .")

                        echo "Tagging image ${imageWithBuildTag} as ${imageWithLatestTag}..."
                        customImage.tag(imageWithLatestTag) // Memberi tag 'latest' ke image yang sama

                        echo "Pushing image ${imageWithBuildTag} to Docker Hub..."
                        customImage.push(env.BUILD_NUMBER) // Mendorong tag dengan BUILD_NUMBER
                        
                        echo "Pushing image ${imageWithLatestTag} to Docker Hub..."
                        customImage.push('latest') // Mendorong tag 'latest'
                    }
                    echo "Docker images pushed successfully."
                }
            }
        }

        stage('Deploy to Docker Swarm') {
            steps {
                echo "Preparing to deploy to Docker Swarm..."
                withCredentials([sshUserPrivateKey(
                    credentialsId: SWARM_MANAGER_SSH_CREDENTIALS_ID,
                    keyFileVariable: 'SSH_PRIVATE_KEY_FILE',    // Jenkins menyediakan path ke file kunci privat sementara
                    usernameVariable: 'SSH_USERNAME'         // Jenkins menyediakan username dari kredensial
                )]) {
                    script {
                        def remoteLogin = "${env.SSH_USERNAME}@${SWARM_MANAGER_IP}"
                        def remoteStackPath = "/opt/stacks/${DOCKER_IMAGE_NAME}" // Path unik per aplikasi
                        def stackFileNameInRepo = "api-gateway-stack.yml" // Pastikan nama file ini ada di repo Anda
                        def stackNameInSwarm = "alifsmart_apigw" // Nama stack di Swarm

                        // Membuat direktori di server remote jika belum ada
                        sh "ssh -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${remoteLogin} \"mkdir -p ${remoteStackPath}\""
                        
                        // Menyalin file stack dari workspace Jenkins ke server remote
                        sh "scp -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ./${stackFileNameInRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        // Variabel environment untuk substitusi di dalam stack file di sisi Swarm manager
                        // Docker stack deploy akan membaca variabel environment ini saat memproses compose file.
                        // Pastikan stack file Anda menggunakan format ${VARIABLE} atau $VARIABLE untuk substitusi.
                        def deployCommand = """
                        export DOCKER_HUB_USERNAME='${DOCKER_HUB_USERNAME}' && \\
                        export DOCKER_IMAGE_NAME='${DOCKER_IMAGE_NAME}' && \\
                        export IMAGE_TAG='latest' && \\
                        export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}' && \\
                        export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}' && \\
                        export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}' && \\
                        echo 'Deploying stack ${stackNameInSwarm} with image ${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:latest...' && \\
                        docker stack deploy \\
                            -c ${remoteStackPath}/${stackFileNameInRepo} \\
                            ${stackNameInSwarm} \\
                            --with-registry-auth
                        """
                        sh "ssh -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${remoteLogin} \"${deployCommand}\""
                        echo "Deployment to Docker Swarm initiated."
                    }
                }
            }
        }
    } // Akhir stages

    post { // Aksi setelah semua stage selesai
        always {
            echo "Pipeline finished."
            // cleanWs() // Opsional: Bersihkan workspace Jenkins setelah build selesai
        }
        success {
            echo "Pipeline sukses! Aplikasi telah di-build, di-push, dan (semoga) terdeploy dengan baik."
            // Tambahkan notifikasi sukses (misalnya ke Slack, Email)
        }
        failure {
            echo "Pipeline gagal! Silakan periksa log untuk detailnya."
            // Tambahkan notifikasi kegagalan
        }
    }
}