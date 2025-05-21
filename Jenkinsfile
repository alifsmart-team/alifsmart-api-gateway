pipeline {
    agent any

    tools {
        git 'Default'
    }

    environment {
        // Docker Hub Configuration
        DOCKER_HUB_USERNAME = 'vitoackerman'
        DOCKER_IMAGE_NAME = 'alifsmart-api-gateway'

        // Redis Credentials (Jenkins Credential IDs)
        ENV_REDIS_HOST = credentials('redis_host')
        ENV_REDIS_PORT = credentials('redis_port')
        ENV_REDIS_TLS_ENABLED = credentials('redis_tls_is_enabled')

        // Swarm Manager Configuration
        SWARM_MANAGER_SSH_CREDENTIALS_ID = 'ssh_credential_id'
        SWARM_MANAGER_IP = '47.84.46.116'
        SWARM_MANAGER_USER = 'root'
        
        // Credential IDs
        DOCKER_HUB_CREDENTIALS_ID = 'docker_credential_id'
        GITHUB_CREDENTIALS_ID = 'github_pat'
    }

    stages {
        stage('Checkout Code') {
            steps {
                git branch: 'main',
                    credentialsId: "${env.GITHUB_CREDENTIALS_ID}",
                    url: 'https://github.com/alifsmart-team/alifsmart-api-gateway.git'
            }
        }

        stage('Install & Test') {
            steps {
                bat '''
                    docker run --rm -v "%CD%:/app" -w /app node:18-alpine ^
                        sh -c "npm ci && npm run test -- --passWithNoTests"
                '''
            }
        }

        stage('Security Scan') {
            steps {
                script {
                    def scanImage = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}:scan-${env.BUILD_NUMBER}"
                    
                    // Build temporary image
                    docker.build(scanImage, "-f Dockerfile .")
                    
                    // Run Trivy scan using Docker
                    bat """
                        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ^
                            aquasec/trivy:latest image ^
                            --exit-code 1 ^
                            --severity CRITICAL,HIGH ^
                            --ignore-unfixed ^
                            --ignore-ids CVE-2024-21538 ^
                            ${scanImage}
                    """
                    
                    // Cleanup
                    bat "docker rmi ${scanImage} || echo Cleanup failed"
                }
            }
        }

        stage('Build & Push Image') {
            steps {
                script {
                    def image = "${env.DOCKER_HUB_USERNAME}/${env.DOCKER_IMAGE_NAME}"
                    
                    docker.withRegistry("https://index.docker.io/v1/", env.DOCKER_HUB_CREDENTIALS_ID) {
                        def builtImage = docker.build("${image}:${env.BUILD_NUMBER}")
                        builtImage.push()
                        builtImage.tag('latest')
                        builtImage.push('latest')
                    }
                }
            }
        }

        stage('Deploy to Swarm') {
            steps {
                sshagent(credentials: [env.SWARM_MANAGER_SSH_CREDENTIALS_ID]) {
                    script {
                        def sshTarget = "${env.SWARM_MANAGER_USER}@${env.SWARM_MANAGER_IP}"
                        def sshOpts = "-o StrictHostKeyChecking=no -o LogLevel=ERROR"
                        def stackPath = "/opt/stacks/${env.DOCKER_IMAGE_NAME}"
                        
                        // Create directory
                        powershell """
                            ssh ${sshOpts} ${sshTarget} "mkdir -p ${stackPath}"
                        """
                        
                        // Copy stack file
                        powershell """
                            scp ${sshOpts} api-gateway-stack.yml ${sshTarget}:${stackPath}/
                        """
                        
                        // Deploy command
                        def deployCmd = """
                            docker stack deploy \
                                -c ${stackPath}/api-gateway-stack.yml \
                                alifsmart_apigw \
                                --with-registry-auth \
                                --prune
                        """.stripIndent().replace('\n', ' ')
                        
                        // Execute deployment
                        powershell """
                            ssh ${sshOpts} ${sshTarget} "${deployCmd}"
                        """
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Pipeline execution completed"
        }
        success {
            echo "SUCCESS: Application deployed to Swarm cluster"
            slackSend color: 'good', message: "Deployment succeeded: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
        failure {
            echo "FAILURE: Pipeline execution failed"
            slackSend color: 'danger', message: "Deployment failed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
    }
}