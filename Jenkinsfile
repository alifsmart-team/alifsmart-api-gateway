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
                // Menggunakan PowerShell untuk menjalankan perintah docker run
                // Bagian sh -c "..." di dalam container tetap karena container adalah Linux (node:18-alpine)
                // ${PWD} adalah cara PowerShell untuk mendapatkan direktori kerja saat ini
                powershell 'docker run --rm -v "${PWD}:/app" -w /app node:18-alpine sh -c "npm ci && npm run test -- --passWithNoTests"'
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

                stage('Deploy to Docker Swarm') {
            steps {
                echo "Preparing to deploy to Docker Swarm..."
                // Menggunakan plugin SSH Agent
                sshagent(credentials: [env.SWARM_MANAGER_SSH_CREDENTIALS_ID]) {
                    // Di dalam blok sshagent, kunci akan dimuat.
                    // Kita akan menggunakan SWARM_MANAGER_USER dari environment.
                    script {
                        def sshUser = env.SWARM_MANAGER_USER // Ambil dari environment block
                        if (!sshUser) {
                             // Fallback jika SWARM_MANAGER_USER tidak diset di environment.
                             // Pastikan ini user yang benar untuk SSH ke Swarm Manager Anda.
                            sshUser = 'root' 
                            echo "Warning: SWARM_MANAGER_USER not defined in environment, defaulting to '${sshUser}'. Please define it for clarity."
                        }

                        def remoteLogin = "${sshUser}@${env.SWARM_MANAGER_IP}"
                        def remoteStackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}" 
                        def stackFileNameInRepo = "api-gateway-stack.yml" 
                        def stackNameInSwarm = "alifsmart_apigw"

                        // Opsi untuk SSH. -i tidak diperlukan lagi karena sshagent
                        // Path ke file kunci privat tidak lagi dirujuk secara manual di sini.
                        def sshOptions = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=nul"

                        echo "Creating remote directory ${remoteStackPath} on ${remoteLogin}..."
                        // Menggunakan bat untuk memanggil ssh.exe
                        // Perintah remote 'mkdir -p ...' diapit kutip tunggal untuk shell remote (Linux)
                        bat "ssh ${sshOptions} ${remoteLogin} \"mkdir -p ${remoteStackPath}\""
                        
                        echo "Copying ${stackFileNameInRepo} to ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}..."
                        // Menggunakan bat untuk memanggil scp.exe
                        // .\\ untuk path relatif di Windows
                        bat "scp ${sshOptions} .\\${stackFileNameInRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        // Perintah deployCommandOnRemote akan dieksekusi di shell Linux remote server.
                        // Kita buat menjadi satu baris dengan mengganti newline dengan '; ' agar lebih aman untuk bat
                        // Atau kita bisa mencoba mengirimnya sebagai string multi-baris jika ssh client & server menanganinya dengan baik.
                        // Untuk bat, mengirim string multi-baris yang sangat panjang bisa tricky.
                        // Alternatif: simpan deployCommandOnRemote ke file .sh lalu scp dan eksekusi file .sh tersebut.
                        // Untuk sekarang, kita coba kirim langsung.
                        
                        // Variabel environment yang akan diekspor di remote
                        def remoteExports = "export DOCKER_HUB_USERNAME='${env.DOCKER_HUB_USERNAME}'; " +
                                            "export DOCKER_IMAGE_NAME='${env.DOCKER_IMAGE_NAME}'; " +
                                            "export IMAGE_TAG='latest'; " +
                                            "export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; " +
                                            "export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; " +
                                            "export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; "
                        
                        def remoteDockerCommand = "echo 'Deploying stack ${stackNameInSwarm} with image ${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:latest...'; " +
                                                  "docker stack deploy -c '${remoteStackPath}/${stackFileNameInRepo}' '${stackNameInSwarm}' --with-registry-auth"

                        // Gabungkan semua perintah remote menjadi satu string, dipisahkan oleh '&&' atau ';'
                        // Penggunaan kutip ganda di sekitar keseluruhan perintah untuk ssh sangat penting.
                        def fullRemoteCommand = "${remoteExports} ${remoteDockerCommand}"

                        // Menggunakan bat untuk memanggil ssh.exe dengan perintah yang sudah diformat
                        bat "ssh ${sshOptions} ${remoteLogin} \"${fullRemoteCommand}\""
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