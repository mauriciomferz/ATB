## Description
<!-- Describe your changes -->

## Type of Change
- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to change)
- [ ] 📝 Documentation update
- [ ] 🔒 Security fix
- [ ] 📦 Dependency update
- [ ] 🏗️ Infrastructure/CI change

## Related Issues
<!-- Link to related issues: Fixes #123, Closes #456 -->

## Risk Assessment
<!-- For OPA policy or authentication changes -->
- [ ] This PR modifies OPA policy
- [ ] This PR modifies authentication/authorization logic
- [ ] This PR modifies cryptographic operations
- [ ] This PR modifies external API integrations

## Testing
<!-- Describe the tests you ran -->

### Test Results
```
<paste test output>
```

- [ ] OPA tests pass (`make test-opa`)
- [ ] Go tests pass (`make test-go`)
- [ ] Lint checks pass (`make lint`)
- [ ] Helm template validates (`helm template charts/atb`)

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
- [ ] Any dependent changes have been merged and published

## Security Checklist
<!-- Required for security-sensitive changes -->
- [ ] No secrets or credentials are committed
- [ ] No PII is logged or exposed
- [ ] Input validation is implemented
- [ ] Error messages don't leak sensitive information

## Screenshots (if applicable)
<!-- Add screenshots to help explain your changes -->

## Additional Notes
<!-- Any additional information for reviewers -->
