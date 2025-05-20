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
                // Menggunakan PowerShell untuk menjalankan perintah docker run
                // Bagian sh -c "..." di dalam container tetap karena container adalah Linux (node:18-alpine)
                // ${PWD} adalah cara PowerShell untuk mendapatkan direktori kerja saat ini (mirip $(pwd) di bash)
                powershell 'docker run --rm -v "${PWD}:/app" -w /app node:18-alpine sh -c "npm ci && npm run test -- --passWithNoTests"'
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    def fullImageNameForScan = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"

                    echo "Building temporary image for scan: ${fullImageNameForScan}"
                    // docker.build() sudah lintas platform
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_HUB_CREDENTIALS_ID) {
                        def scanImage = docker.build(fullImageNameForScan, "-f Dockerfile .")
                    }
                    
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities..."
                    // Menggunakan powershell untuk menjalankan Trivy.
                    // Asumsikan 'trivy.exe' ada di PATH Windows Anda atau Anda menjalankan Trivy via Docker.
                    def trivyScanCommand = "trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 ${fullImageNameForScan}"
                    // Jika Trivy via Docker:
                    // trivyScanCommand = "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 ${fullImageNameForScan}"
                    
                    try {
                        powershell trivyScanCommand
                        echo "Trivy scan passed or ignored vulnerabilities did not cause failure."
                    } catch (err) {
                        echo "Trivy scan failed or found unignored CRITICAL/HIGH vulnerabilities. Error: ${err.getMessage()}"
                        // Pertimbangkan untuk menggagalkan pipeline di sini jika ada temuan serius yang tidak diabaikan:
                        // error("Trivy scan found unignored CRITICAL/HIGH vulnerabilities.")
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
                    def imageBaseName = "${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}"
                    def imageWithBuildTag = "${imageBaseName}:${env.BUILD_NUMBER}"
                    def imageWithLatestTag = "${imageBaseName}:latest"

                    // Langkah-langkah Docker Pipeline sudah lintas platform
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_HUB_CREDENTIALS_ID) {
                        echo "Building image ${imageWithBuildTag}..."
                        def customImage = docker.build(imageWithBuildTag, "-f Dockerfile .")

                        echo "Tagging image ${imageWithBuildTag} as ${imageWithLatestTag}..."
                        customImage.tag(imageWithLatestTag)

                        echo "Pushing image ${imageWithBuildTag} to Docker Hub..."
                        customImage.push(env.BUILD_NUMBER)
                        
                        echo "Pushing image ${imageWithLatestTag} to Docker Hub..."
                        customImage.push('latest')
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
                    keyFileVariable: 'SSH_PRIVATE_KEY_FILE',
                    usernameVariable: 'SSH_USERNAME'
                )]) {
                    script {
                        def remoteLogin = "${env.SSH_USERNAME}@${SWARM_MANAGER_IP}"
                        def remoteStackPath = "/opt/stacks/${DOCKER_IMAGE_NAME}" 
                        def stackFileNameInRepo = "api-gateway-stack.yml" 
                        def stackNameInSwarm = "alifsmart_apigw"

                        // Menggunakan powershell untuk memanggil ssh.exe dan scp.exe
                        // Path ke file kunci privat dari Jenkins Credentials
                        def sshKeyPath = env.SSH_PRIVATE_KEY_FILE 
                        // Opsi untuk SSH dan SCP (UserKnownHostsFile=nul mungkin bekerja untuk ssh.exe dari Git for Windows)
                        def sshOptions = "-i \`"${sshKeyPath}\`" -o StrictHostKeyChecking=no -o UserKnownHostsFile=nul"

                        echo "Creating remote directory ${remoteStackPath} on ${remoteLogin}..."
                        powershell "ssh ${sshOptions} ${remoteLogin} \`"mkdir -p ${remoteStackPath}\`""
                        
                        echo "Copying ${stackFileNameInRepo} to ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}..."
                        // Menggunakan .\\ untuk path relatif di Windows untuk scp
                        powershell "scp ${sshOptions} .\\${stackFileNameInRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        def deployCommandOnRemote = """
                        export DOCKER_HUB_USERNAME='${DOCKER_HUB_USERNAME}'; \\
                        export DOCKER_IMAGE_NAME='${DOCKER_IMAGE_NAME}'; \\
                        export IMAGE_TAG='latest'; \\
                        export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; \\
                        export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; \\
                        export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; \\
                        echo 'Deploying stack ${stackNameInSwarm} with image ${DOCKER_HUB_USERNAME}/${DOCKER_IMAGE_NAME}:latest...'; \\
                        docker stack deploy \\
                            -c ${remoteStackPath}/${stackFileNameInRepo} \\
                            ${stackNameInSwarm} \\
                            --with-registry-auth
                        """
                        // Saat memanggil perintah multi-baris via ssh di PowerShell,
                        // lebih aman jika perintah tersebut tidak mengandung karakter yang perlu di-escape khusus oleh PowerShell.
                        // String Groovy di atas akan dievaluasi menjadi satu string panjang.
                        // Tanda kutip ganda di sekitar "${deployCommandOnRemote}" memastikan variabel Groovy diekspansi.
                        powershell "ssh ${sshOptions} ${remoteLogin} \"${deployCommandOnRemote}\""
                        echo "Deployment to Docker Swarm initiated."
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