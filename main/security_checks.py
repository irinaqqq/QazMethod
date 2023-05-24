import random

def perform_software_security_test(website_url):
    # Simulating the software security test
    # This is just an example implementation

    # Assume we have a list of known vulnerabilities
    known_vulnerabilities = [
        'SQL Injection',
        'Cross-Site Scripting (XSS)',
        'Remote Code Execution',
        'Server Misconfiguration',
    ]

    # Simulating the check by randomly determining if issues are found
    if random.random() < 0.8:
        # No issues found
        issues_found = []
    else:
        # Randomly select vulnerabilities as issues
        num_issues = random.randint(1, len(known_vulnerabilities))
        issues_found = random.sample(known_vulnerabilities, num_issues)

    return issues_found


def perform_compliance_test(website_url):
    # Simulating the compliance test
    # This is just an example implementation

    # Assume we have a list of compliance issues
    compliance_issues = [
        'Missing Privacy Policy',
        'Insecure Data Storage',
        'Non-compliant Third-Party Integrations',
        'Lack of Accessibility Compliance',
    ]

    # Simulating the check by randomly determining if issues are found
    if random.random() < 0.8:
        # No issues found
        issues_found = []
    else:
        # Randomly select compliance issues as found issues
        num_issues = random.randint(1, len(compliance_issues))
        issues_found = random.sample(compliance_issues, num_issues)

    return issues_found

def perform_content_security_policy_test(website_url):
    # Simulating the content security policy test
    # This is just an example implementation

    # Assume we have a dictionary mapping content security policy tests to their status
    content_security_tests = {
        'Content Security Policy Test 1': 'MISSING',
        'Content Security Policy Test 2': 'FOUND',
        'Content Security Policy Test 3': 'FOUND',
    }

    # Simulating the test by randomly determining if issues are found
    if random.random() < 0.8:
        # No issues found
        issues_found = []
    else:
        # Select missing content security policy tests as found issues
        issues_found = [test for test, status in content_security_tests.items() if status == 'MISSING']

    return issues_found

def perform_headers_security_test(website_url):
    # Simulating the headers security test
    # This is just an example implementation

    # Assume we have a dictionary mapping header security tests to their status
    header_security_tests = {
        'Headers Security Test 1': 'NO MAJOR ISSUES FOUND',
        'Headers Security Test 2': 'ISSUES FOUND',
        'Headers Security Test 3': 'NO ISSUES FOUND',
    }

    # Simulating the test by randomly determining if issues are found
    if random.random() < 0.8:
        # No major issues found
        issues_found = []
    else:
        # Select header security tests with issues as found issues
        issues_found = [test for test, status in header_security_tests.items() if status != 'NO MAJOR ISSUES FOUND']

    return issues_found