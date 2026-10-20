# Login Security System

## Overview

The Login Security System is a Java application that demonstrates
secure user registration, authentication, password management, and
security event logging.

The project uses a relational SQLite database to store user accounts
and security-related information.

## Technologies Used

- Java 21
- Maven
- SQLite
- JDBC
- JUnit 5
- Git and GitHub

## Features

### User Registration
- Register users with unique usernames.
- Validate password strength.
- Hash passwords before storing them.
- Prevent duplicate usernames.

### Authentication
- Verify user credentials during login.
- Track failed login attempts.
- Support account locking.
- Apply login rate limiting.

### Password Security
- Change passwords after verifying the current password.
- Reject weak passwords.
- Maintain password history to prevent password reuse.
- Reset failed login attempts after a successful password change.

### Security Auditing
- Record security events such as login attempts and password changes.
- Store timestamps and IP address information with security logs.
- Retrieve audit logs for individual users.
- Count selected security events.

## Database

The application uses SQLite with tables for:

- `users` — user accounts and account security status.
- `security_logs` — recorded security events.
- `password_history` — previously used password hashes.

Local database files are excluded from Git.

## Prerequisites

Install the following:

- JDK 21 or a compatible Java development environment.
- Apache Maven.

## Running the Tests

Clone the repository and navigate to the project directory.

Run the complete test suite:

```bash
mvn clean test# -Login_security_system
