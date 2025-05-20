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
                // Gunakan ${PWD} untuk path saat ini di PowerShell
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
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_HUB_CREDENTIALS_ID) {
                        def scanImage = docker.build(fullImageNameForScan, "-f Dockerfile .")
                    }
                    
                    echo "Scanning image ${fullImageNameForScan} for vulnerabilities using Docker..."
                    // Menggunakan powershell untuk menjalankan Trivy via Docker
                    // Mount Docker socket agar Trivy di dalam container bisa mengakses image lokal yang baru di-build
                    // Perhatikan path Docker socket untuk Docker Desktop di Windows
                    // Docker Desktop biasanya membuat named pipe yang bisa di-mount
                    // atau Docker CLI akan menanganinya.
                    // Umumnya, `-v /var/run/docker.sock:/var/run/docker.sock` bekerja untuk Linux.
                    // Untuk Windows dengan Docker Desktop, Docker CLI biasanya sudah bisa mengakses daemon.
                    // Jika ada masalah, path socket di Windows bisa jadi '//./pipe/docker_engine'
                    // Coba tanpa mount socket dulu jika image sudah di-resolve Docker daemon.
                    // Jika image ${fullImageNameForScan} ada di daemon lokal, Trivy dalam container mungkin butuh akses ke daemon.
                    powershell "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --exit-code 1 --severity CRITICAL,HIGH --ignore-unfixed ${fullImageNameForScan}"
                    
                    echo "Cleaning up scan image (optional)..."
                    try {
                        powershell "docker rmi ${fullImageNameForScan}"
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
                    def imageWithBuildTag = "${imageBaseName}:${env.BUILD_NUMBER}"
                    def imageWithLatestTag = "${imageBaseName}:latest"

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
                    keyFileVariable: 'SSH_PRIVATE_KEY_FILE',    // Jenkins menyediakan path ke file kunci privat sementara
                    usernameVariable: 'SSH_USERNAME'         // Jenkins menyediakan username dari kredensial
                )]) {
                    script {
                        def remoteLogin = "${env.SSH_USERNAME}@${SWARM_MANAGER_IP}"
                        def remoteStackPath = "/opt/stacks/${DOCKER_IMAGE_NAME}" 
                        def stackFileNameInRepo = "api-gateway-stack.yml" 
                        def stackNameInSwarm = "alifsmart_apigw"

                        // Membuat direktori di server remote jika belum ada
                        // Menggunakan powershell untuk memanggil ssh.exe
                        // Path ke file kunci privat akan ada di env.SSH_PRIVATE_KEY_FILE
                        // Untuk UserKnownHostsFile=/dev/null di Windows, alternatifnya adalah menonaktifkannya dengan cara lain
                        // atau menggunakan $null jika PowerShell menginterpretasikannya. Untuk kesederhanaan,
                        // kita bisa mencoba tanpa UserKnownHostsFile atau menggunakan nul jika ssh.exe mendukungnya.
                        // Cara paling aman adalah menambahkan host key ke known_hosts Windows atau Jenkins.
                        powershell "ssh -i \"${env.SSH_PRIVATE_KEY_FILE}\" -o StrictHostKeyChecking=no -o UserKnownHostsFile=nul ${remoteLogin} \"mkdir -p ${remoteStackPath}\""
                        
                        // Menyalin file stack dari workspace Jenkins ke server remote
                        powershell "scp -i \"${env.SSH_PRIVATE_KEY_FILE}\" -o StrictHostKeyChecking=no -o UserKnownHostsFile=nul .\\${stackFileNameInRepo} ${remoteLogin}:${remoteStackPath}/${stackFileNameInRepo}"
                        
                        echo "Deploying stack ${stackNameInSwarm} on Swarm Manager ${remoteLogin}..."
                        // Perintah deployCommand akan dieksekusi di shell Linux remote server, jadi sintaks export dll. tetap
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
                        // Menggunakan powershell untuk memanggil ssh.exe dengan perintah multi-baris
                        // Perlu escape karakter khusus PowerShell jika ada di dalam deployCommand,
                        // tapi karena deployCommand adalah string Groovy yang akan dieksekusi di remote, ini seharusnya aman.
                        powershell "ssh -i \"${env.SSH_PRIVATE_KEY_FILE}\" -o StrictHostKeyChecking=no -o UserKnownHostsFile=nul ${remoteLogin} \"${deployCommand}\""
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