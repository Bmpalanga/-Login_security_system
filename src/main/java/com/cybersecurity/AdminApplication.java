package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.model.User;
import com.cybersecurity.service.AdminService;

import java.util.List;
import java.util.Optional;
import java.util.Scanner;

public class AdminApplication {

    public static void main(String[] args) {

        DatabaseInitializer.initializeDatabase();

        AdminService adminService = new AdminService();

        Scanner scanner = new Scanner(System.in);

        System.out.println("================================");
        System.out.println("   LOGIN SECURITY ADMIN PANEL");
        System.out.println("================================");

        System.out.print("Enter username: ");

        String username = scanner.nextLine();

        Optional<User> user =
                adminService.findUser(username);

        if (user.isEmpty()) {

            System.out.println(
                    "User not found."
            );

            return;
        }

        User foundUser = user.get();

        System.out.println();
        System.out.println("User Information");
        System.out.println("----------------------------");
        System.out.println(
                "Username: " + foundUser.getUsername()
        );
        System.out.println(
                "Failed attempts: "
                        + foundUser.getFailedAttempts()
        );
        System.out.println(
                "Locked: " + foundUser.isLocked()
        );

        System.out.println();
        System.out.println("Security Logs");
        System.out.println("----------------------------");

        List<String> logs =
                adminService.getSecurityLogs(username);

        if (logs.isEmpty()) {

            System.out.println(
                    "No security events found."
            );

        } else {

            for (String log : logs) {
                System.out.println(log);
            }
        }

        scanner.close();
    }
}