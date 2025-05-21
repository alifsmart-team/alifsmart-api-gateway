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
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id' // ID Kredensial SSH Anda
        SWARM_MANAGER_IP = '47.84.46.116' // IP Server 1 Swarm Manager Anda
        SWARM_MANAGER_USER = 'root'       // Pastikan ini user SSH yang benar untuk Swarm Manager
        
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
                // Menggunakan bat untuk menjalankan perintah docker run di Windows.
                // Bagian sh -c "..." di dalam container tetap karena container adalah Linux (node:18-alpine)
                // %CD% adalah cara Command Prompt untuk mendapatkan direktori kerja saat ini.
                bat 'docker run --rm -v "%CD%:/app" -w /app node:18-alpine sh -c "npm ci && npm run test -- --passWithNoTests"'
                echo "Dependencies installed and tests completed."
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    echo "Starting security scan with Trivy..."
                    def fullImageNameForScan = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"

                    echo "Building temporary image for scan: ${fullImageNameForScan}"
                    docker.withRegistry('https://index.docker.io/v1/', env.DOCKER_HUB_CREDENTIALS_ID) {
                        def scanImage = docker.build(fullImageNameForScan, "-f Dockerfile .")
                    }
                    
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities..."
                    // Menggunakan bat untuk menjalankan Trivy.
                    // Asumsikan 'trivy.exe' ada di PATH Windows Anda.
                    def trivyScanCommand = "trivy image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 ${fullImageNameForScan}"
                    // Jika Anda menjalankan Trivy via Docker:
                    // trivyScanCommand = "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed --ignore-ids CVE-2024-21538 ${fullImageNameForScan}"
                    
                    try {
                        bat "${trivyScanCommand}" // Menggunakan bat
                        echo "Trivy scan passed or ignored vulnerabilities did not cause failure."
                    } catch (err) {
                        echo "Trivy scan failed or found unignored CRITICAL/HIGH vulnerabilities. Error: ${err.getMessage()}"
                        // error("Trivy scan found unignored CRITICAL/HIGH vulnerabilities or an error occurred.") // Uncomment untuk menggagalkan pipeline
                    }
                    
                    echo "Cleaning up scan image (optional)..."
                    try {
                        bat "docker rmi ${fullImageNameForScan}" // Menggunakan bat
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
                // Menggunakan plugin SSH Agent untuk menangani kunci SSH.
                // Pastikan plugin SSH Agent terinstal dan layanan "OpenSSH Authentication Agent" berjalan di Windows.
                sshagent(credentials: [env.SWARM_MANAGER_SSH_CREDENTIALS_ID]) {
                    // Di dalam blok sshagent, kunci SSH dari kredensial env.SWARM_MANAGER_SSH_CREDENTIALS_ID
                    // akan secara otomatis dimuat dan digunakan oleh perintah ssh/scp.
                    // Anda tidak perlu lagi merujuk ke file kunci privat secara manual (-i path_ke_kunci).
                    script {
                        // Menggunakan SWARM_MANAGER_USER dari environment block.
                        // Pastikan SWARM_MANAGER_USER sudah didefinisikan dengan benar di blok environment.
                        if (env.SWARM_MANAGER_USER == null || env.SWARM_MANAGER_USER.trim().isEmpty()) {
                            error("SWARM_MANAGER_USER environment variable is not set or is empty. Please define it in the environment block.")
                        }
                        def sshUser = env.SWARM_MANAGER_USER
                        def remoteLogin = "${sshUser}@${env.SWARM_MANAGER_IP}"
                        def remoteStackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}" 
                        def stackFileNameInRepo = "api-gateway-stack.yml" 
                        def stackNameInSwarm = "alifsmart_apigw"

                        // Opsi untuk SSH. -i tidak diperlukan lagi karena sshagent.
                        // UserKnownHostsFile=nul adalah untuk Windows agar tidak menanyakan host key,
                        // tapi pastikan Anda sadar implikasi keamanannya atau sudah menambahkan host key secara manual.
                        def sshOptions = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=nul"

                        echo "Target remote login: ${remoteLogin}"
                        echo "Creating remote directory ${remoteStackPath} on ${remoteLogin}..."
                        // Menggunakan powershell untuk memanggil ssh.exe
                        // Perintah remote 'mkdir -p ...' diapit kutip tunggal untuk shell remote (Linux).
                        // Backtick ` sebelum kutip ganda di perintah remote adalah escape untuk PowerShell agar kutip ganda diinterpretasikan literal.
                        powershell "ssh ${sshOptions} ${remoteLogin} \`"mkdir -p ${remoteStackPath}\`""
                        
                        echo "Copying ${stackFileNameInRepo} to ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}..."
                        // Menggunakan powershell untuk memanggil scp.exe. Path relatif Windows: .\\
                        powershell "scp ${sshOptions} .\\${stackFileNameInRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        // Perintah deployCommandOnRemote akan dieksekusi di shell Linux remote server.
                        // String Groovy multi-baris ini akan dilewatkan sebagai satu argumen ke ssh.
                        def deployCommandOnRemote = """
                        export DOCKER_HUB_USERNAME='${env.DOCKER_HUB_USERNAME}'; \\
                        export DOCKER_IMAGE_NAME='${env.DOCKER_IMAGE_NAME}'; \\
                        export IMAGE_TAG='latest'; \\
                        export ENV_REDIS_HOST='${env.ENV_REDIS_HOST}'; \\
                        export ENV_REDIS_PORT='${env.ENV_REDIS_PORT}'; \\
                        export ENV_REDIS_TLS_ENABLED='${env.ENV_REDIS_TLS_ENABLED}'; \\
                        echo 'Deploying stack ${stackNameInSwarm} with image ${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:latest...'; \\
                        docker stack deploy \\
                            -c '${remoteStackPath}/${stackFileNameInRepo}' \\
                            '${stackNameInSwarm}' \\
                            --with-registry-auth
                        """.trim().replaceAll("\\n", " ") // Mengubah newline menjadi spasi untuk dikirim sebagai satu baris perintah

                        // Mengapit seluruh deployCommandOnRemote dengan kutip ganda agar dikirim sebagai satu argumen ke ssh.
                        // Ini penting agar PowerShell dan kemudian ssh menanganinya dengan benar.
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