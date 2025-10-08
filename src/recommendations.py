# --- Recommendation Engine ---
# This dictionary is the core of the recommendation engine. It maps a check ID (like 'IAM_WILDCARD') to a detailed, four-part recommendation.

RECOMMENDATIONS = {
    'IAM_WILDCARD': {
        'finding': "Overly Permissive IAM Role",
        'risk': "This role grants broad permissions (using a wildcard '*'), which violates the principle of least privilege. If this function is compromised, an attacker could potentially access or damage many more resources than necessary.",
        'advice': "Review the function's code to determine the exact permissions it needs. Replace the wildcard with a specific, limited set of actions (e.g., replace 's3:*' with 's3:GetObject').",
        'doc_link': "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
    },
    'SECRET_IN_ENV_NAME': {
        'finding': "Potential Secret in Environment Variable Name",
        'risk': "Storing secrets like API keys or passwords in plaintext environment variables is a security risk. These values can be exposed in logs, version control, or build artifacts.",
        'advice': "Store this secret in AWS Secrets Manager or AWS Systems Manager Parameter Store (SecureString). Then, update your function's IAM role to grant it permission to read the secret at runtime.",
        'doc_link': "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"
    },
    'SECRET_IN_ENV_VALUE': {
        'finding': "High-Entropy Value Detected (Likely a Secret)",
        'risk': "A value with high randomness was found in an environment variable, which strongly suggests it is a secret key. Storing secrets in plaintext is a security risk.",
        'advice': "Store this secret in AWS Secrets Manager or Parameter Store. Update the function's IAM role to allow it to fetch the secret at runtime.",
        'doc_link': "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"
    },
    'INSECURE_TRIGGER': {
        'finding': "Insecure API Gateway Trigger",
        'risk': "This function is triggered by a public API Gateway endpoint that has no authorization. This means anyone on the internet can invoke your function, which could lead to unauthorized access or high costs.",
        'advice': "Secure the API Gateway endpoint. You can use an AWS IAM authorizer, a Lambda authorizer, or a Cognito user pool to ensure only authenticated and authorized users can access the API.",
        'doc_link': "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html"
    },
    'MEMORY_OVERPROVISIONED': {
        'finding': "Memory is Over-Provisioned",
        'risk': "This function is allocated significantly more memory than it has recently used. This leads to unnecessary costs, as you are billed for the memory you allocate, not what you use.",
        'advice': "Consider lowering the memory configuration to be closer to the 'Max Used' value. AWS Lambda allocates CPU proportional to memory, so remember to test your function's performance after making the change.",
        'doc_link': "https://docs.aws.amazon.com/lambda/latest/dg/configuration-memory.html"
    },
    'TIMEOUT_SUBOPTIMAL': {
        'finding': "Suboptimal Timeout Configured",
        'risk': "The timeout is much longer than the function's average execution time. If the function hangs or enters an infinite loop due to a bug, it will run for the full timeout duration, leading to high, unexpected costs.",
        'advice': "Set the timeout to a value that is closer to your function's expected maximum execution time. A good starting point is 3x the average duration to provide a safe buffer.",
        'doc_link': "https://docs.aws.amazon.com/lambda/latest/dg/configuration-timeout.html"
    }
}