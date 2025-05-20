// Jenkinsfile
pipeline {
    agent any // Atau tentukan agent spesifik yang memiliki Docker dan Git terinstal

    tools {
        // Pastikan 'Default' adalah nama instalasi Git yang dikonfigurasi
        // di Manage Jenkins > Tools (atau Global Tool Configuration)
        // Jika Anda menamakannya lain (misal: 'Git_Lokal'), sesuaikan di sini.
        git 'Default'
    }

    environment {
        // Konfigurasi Docker Image
        DOCKER_HUB_USERNAME = 'vitoackerman' // Username Docker Hub atau organisasi
        DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'
        // DOCKER_REGISTRY_URL bisa diset kalo pake private registry selain Docker Hub (misal: 'your.private.registry.com')
        // Untuk Docker Hub, bisa dikosongkan atau 'docker.io'

        // Kredensial untuk Redis (diambil dari Jenkins Credentials)
        // Pastikan ID ini ('f8077...') sesuai dengan ID credential 'Secret text' di Jenkins Anda
        ENV_REDIS_HOST = credentials('f80778c6-6904-49cf-8b86-e909905fe4ac')
        ENV_REDIS_PORT = credentials('460e1099-ca40-4918-8d90-7415c4b94b31')
        ENV_REDIS_TLS_ENABLED = credentials('870dd061-f6ba-49dc-8e22-450af5e1d528')
        // REDIS_PASSWORD dan JWT_SECRET akan di-handle via Docker Secrets di Swarm.

        // Kredensial SSH untuk Docker Swarm Manager
        // Pastikan ID ini ('0c68d...') sesuai dengan ID credential 'SSH Username with private key' di Jenkins Anda
        SWARM_MANAGER_SSH_CREDENTIALS_ID = '0c68d9d8-670b-497f-9106-031cdd2a6eb5'
        SWARM_MANAGER_IP = '47.84.46.116'
        
        // Kredensial Docker Hub untuk 'docker login'
        // Pastikan ID ini ('dockerhub-vitoackerman-login') sesuai dengan ID credential 'Username with password'
        // untuk Docker Hub Anda di Jenkins. Username di credential ini adalah username Docker Hub,
        // dan password-nya adalah Personal Access Token Docker Hub atau password Docker Hub Anda.
        DOCKER_HUB_CREDENTIALS_ID = 'bb4fa84d-a3b2-40a0-8a7e-b7d566d795d7'

        // Kredensial GitHub untuk checkout
        // Ganti 'github-m4yestik-pat' dengan ID kredensial GitHub (Username with password, passwordnya adalah PAT)
        // yang telah Anda buat di Jenkins sebelumnya.
        GITHUB_CREDENTIALS_ID = 'cb5e191b-7046-4d8d-a146-25148ed7d6a4' // <<< PERHATIKAN DAN SESUAIKAN ID INI
    }

    stages {
        stage('Checkout') {
            steps {
                echo "Checking out from GitHub repository: https://github.com/m4yestik/alifsmart-api-gateway.git on branch main"
                // Menggunakan kredensial GitHub yang telah ditentukan di environment
                git branch: 'main',
                    credentialsId: env.GITHUB_CREDENTIALS_ID, // Mengambil dari environment variable
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git'
                echo "Checkout complete."
            }
        }

        stage('Install Dependencies & Test') {
            steps {
                echo "Installing dependencies and running tests..."
                // 'npm ci' lebih disarankan untuk CI/CD karena install dependencies persis dari package-lock.json
                // dan biasanya lebih cepat. 'npm ci' juga akan menginstall devDependencies.
                // Pastikan agent Jenkins memiliki Docker terinstal dan bisa menjalankan container.
                sh 'docker run --rm -v $(pwd):/app -w /app node:18-alpine sh -c "npm ci && npm test"'
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    // Pastikan Trivy terinstall di agent atau bisa dijalankan via Docker
                    // Jika Trivy tidak terinstal di agent, Anda bisa menjalankannya via Docker, contoh:
                    // def trivyCommand = "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v \$(pwd)/.trivycache:/root/.cache/ aquasec/trivy:latest"
                    // Untuk kesederhanaan, diasumsikan Trivy ada di PATH agent atau akan diinstal manual jika perlu.
                    // Jika menggunakan Trivy via Docker, pastikan Docker socket ter-mount jika scan image lokal.

                    def fullImageNameForScan = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:scan-${env.BUILD_ID}"
                    
                    echo "Building temporary image for scan: ${fullImageNameForScan}"
                    sh "docker build -f Dockerfile -t ${fullImageNameForScan} ."
                    
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities..."
                    // Gagal_kan pipeline jika ada vulnerability CRITICAL atau HIGH
                    // Jika trivy tidak ada di PATH, ganti dengan perintah docker run untuk trivy.
                    // Contoh jika trivy di PATH:
                    sh "trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed ${fullImageNameForScan}"
                    // Contoh jika trivy via Docker:
                    // sh "docker run --rm aquasec/trivy:latest image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed ${fullImageNameForScan}"
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

                    // Login ke Docker Hub menggunakan Jenkins Credentials
                    // Pastikan DOCKER_HUB_CREDENTIALS_ID adalah tipe "Username with password"
                    echo "Logging in to Docker Hub as ${DOCKER_HUB_USERNAME}..."
                    withCredentials([usernamePassword(credentialsId: DOCKER_HUB_CREDENTIALS_ID, usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                        // Gunakan docker.io sebagai target registry untuk Docker Hub
                        sh "echo \"${DOCKER_PASS}\" | docker login -u \"${DOCKER_USER}\" --password-stdin docker.io"
                    }
                    echo "Docker login successful."
                    
                    echo "Building image ${imageWithBuildTag}..."
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
                // Menggunakan Jenkins Credentials untuk SSH dengan Private Key
                withCredentials([sshUserPrivateKey(
                    credentialsId: SWARM_MANAGER_SSH_CREDENTIALS_ID,
                    keyFileVariable: 'SSH_PRIVATE_KEY_FILE', // Variabel Jenkins yang nyimpen path ke private key sementara
                    usernameVariable: 'SSH_USERNAME' // Variabel Jenkins yang nyimpen username dari credential (akan jadi 'root')
                )]) {
                    script {
                        def remoteLogin = "${env.SSH_USERNAME}@${SWARM_MANAGER_IP}" // Jadi "root@47.84.46.116" jika username di credential adalah root
                        def remoteStackPath = "/opt/stacks/alifsmart-api-gateway" // Path di server Swarm buat nyimpen stack file
                        def stackFileNameOnRepo = "api-gateway-stack.yml" // Nama stack file di repo (pastikan ada di workspace)
                        def stackNameInSwarm = "alifsmart_apigw"

                        echo "Preparing remote directory ${remoteStackPath} on ${remoteLogin}..."
                        // PERHATIAN KEAMANAN: Opsi -o StrictHostKeyChecking=no dan -o UserKnownHostsFile=/dev/null
                        // mem-bypass host key checking. Ini memiliki implikasi keamanan (risiko Man-in-the-Middle).
                        // Cara lebih aman: tambahkan host key server target (47.84.46.116) ke known_hosts Jenkins agent,
                        // atau kelola via fitur "Known Hosts Management" jika tersedia di Jenkins.
                        sh "ssh -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${remoteLogin} \"mkdir -p ${remoteStackPath}\""
                        
                        echo "Copying ${stackFileNameOnRepo} to ${remoteLogin}:${remoteStackPath}/${stackFileNameOnRepo}..."
                        // Pastikan file stackFileNameOnRepo (api-gateway-stack.yml) ada di root workspace Jenkins setelah checkout
                        sh "scp -i ${env.SSH_PRIVATE_KEY_FILE} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ./${stackFileNameOnRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameOnRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        // Variabel environment Jenkins (ENV_REDIS_HOST, dll.) akan di-substitute di sini SEBELUM dikirim ke remote server.
                        // Pastikan api-gateway-stack.yml menggunakan placeholder seperti ${ENV_REDIS_HOST} atau $ENV_REDIS_HOST.
                        // Kredensial sensitif (password, jwt secret) HARUS merujuk ke Docker Secrets Swarm di dalam stack file.
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
            // Bersih-bersih image lokal di Jenkins agent kalo perlu
            script {
                echo "Pipeline finished. Starting cleanup (optional)..."
                def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
                def imageWithBuildTag = "${imageBaseName}:${env.BUILD_ID}"
                def fullImageNameForScan = "${imageBaseName}:scan-${env.BUILD_ID}"

                // Hati-hati dengan `|| true` jika ingin memastikan error cleanup tidak mengganggu status pipeline
                // sh "docker rmi ${imageWithBuildTag} || true" 
                // sh "docker rmi ${fullImageNameForScan} || true"
                // sh "docker image prune -f || true" // Membersihkan dangling images
                echo "Cleanup process finished."
            }
        }
        success {
            echo "Pipeline sukses! API Gateway udah diupdate dan (semoga) terdeploy dengan selamat."
            // Notifikasi ke Slack, Email, dll.
        }
        failure {
            echo "Waduh, pipeline gagal nih, bos! Cek lognya buruan, ada yang gak beres."
            // Notifikasi error
        }
    }
}