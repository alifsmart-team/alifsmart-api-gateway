pipeline {
    agent any

    tools {
        git 'Default'
    }

    environment {
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'
        ENV_REDIS_HOST = credentials('redis_host')
        ENV_REDIS_PORT = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled')
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id'
        SWARM_MANAGER_IP = '47.84.46.116'
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'
        GITHUB_CREDENTIALS_ID = 'github_pat'
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    credentialsId: "${env.GITHUB_CREDENTIALS_ID}",
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git'
            }
        }

        stage('Install Dependencies & Test') {
            steps {
                // PERBAIKAN 1: Gunakan $env:PWD untuk Windows
                powershell "docker run --rm -v '$($env:PWD):/app' -w /app node:18-alpine sh -c 'npm ci && npm run test -- --passWithNoTests'"
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                script {
                    def fullImageNameForScan = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"
                    
                    // Build image
                    docker.withRegistry('https://index.docker.io/v1/', env.DOCKER_HUB_CREDENTIALS_ID) {
                        docker.build(fullImageNameForScan, "-f Dockerfile .")
                    }
                    
                    // PERBAIKAN 2: Gunakan Trivy via Docker
                    powershell """
                        docker run --rm `
                            -v //var/run/docker.sock:/var/run/docker.sock `
                            aquasec/trivy:latest `
                            image --exit-code 1 `
                            --severity CRITICAL,HIGH `
                            --ignore-unfixed ${fullImageNameForScan}
                    """
                    
                    // Cleanup
                    powershell "docker rmi ${fullImageNameForScan} || echo 'Cleanup failed but continuing...'"
                }
            }
        }

        stage('Build & Push Docker Image') {
            steps {
                script {
                    def imageWithBuildTag = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:${env.BUILD_NUMBER}"
                    
                    docker.withRegistry('https://index.docker.io/v1/', env.DOCKER_HUB_CREDENTIALS_ID) {
                        def customImage = docker.build(imageWithBuildTag, "-f Dockerfile .")
                        customImage.push()
                        customImage.tag('latest')
                        customImage.push()
                    }
                }
            }
        }

        stage('Deploy to Docker Swarm') {
            steps {
                withCredentials([sshUserPrivateKey(
                    credentialsId: "${env.SWARM_MANAGER_SSH_CREDENTIALS_ID}",
                    keyFileVariable: 'SSH_PRIVATE_KEY_FILE',
                    usernameVariable: 'SSH_USERNAME'
                )]) {
                    script {
                        def remoteLogin = "${env.SSH_USERNAME}@${env.SWARM_MANAGER_IP}"
                        def stackFileName = "api-gateway-stack.yml"
                        
                        // PERBAIKAN 3: SSH options untuk Windows
                        powershell """
                            ssh -i "${env.SSH_PRIVATE_KEY_FILE}" `
                                -o StrictHostKeyChecking=no `
                                -o UserKnownHostsFile='$null' `
                                ${remoteLogin} "
                                mkdir -p /opt/stacks/${env.DOCKER_IMAGE_NAME} && 
                                docker stack deploy `
                                    -c /opt/stacks/${env.DOCKER_IMAGE_NAME}/${stackFileName} `
                                    alifsmart_apigw `
                                    --with-registry-auth
                            "
                        """
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline selesai"
            // Bersihkan workspace jika perlu
            // cleanWs()
        }
    }
}