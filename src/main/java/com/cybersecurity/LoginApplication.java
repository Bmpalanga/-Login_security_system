package com.cybersecurity;

import com.cybersecurity.database.DatabaseInitializer;
import com.cybersecurity.service.AuthService;

import java.util.Scanner;

public class LoginApplication {

    public static void main(String[] args) {

        DatabaseInitializer.initializeDatabase();

        AuthService authService = new AuthService();

        Scanner scanner = new Scanner(System.in);

        boolean running = true;

        System.out.println("================================");
        System.out.println("      LOGIN SECURITY SYSTEM");
        System.out.println("================================");

        while (running) {

            System.out.println();
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Choose an option: ");

            String choice = scanner.nextLine();

            switch (choice) {

                case "1":
                    registerUser(scanner, authService);
                    break;

                case "2":
                    loginUser(scanner, authService);
                    break;

                case "3":
                    running = false;
                    System.out.println("Goodbye!");
                    break;

                default:
                    System.out.println(
                            "Invalid option. Please choose 1, 2, or 3."
                    );
            }
        }

        scanner.close();
    }

    private static void registerUser(
            Scanner scanner,
            AuthService authService
    ) {

        System.out.println();
        System.out.println("---------- REGISTER ----------");

        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        System.out.print("Enter user ID: ");

        String idInput = scanner.nextLine();

        int id;

        try {

            id = Integer.parseInt(idInput);

        } catch (NumberFormatException e) {

            System.out.println(
                    "Invalid user ID. Please enter a number."
            );

            return;
        }

        try {

            authService.registerUser(
                    id,
                    username,
                    password
            );

            System.out.println(
                    "Registration successful!"
            );

        } catch (IllegalArgumentException e) {

            System.out.println(
                    "Registration failed: "
                            + e.getMessage()
            );
        }

    }

    private static void loginUser(
            Scanner scanner,
            AuthService authService
    ) {

        System.out.println();
        System.out.println("------------ LOGIN ------------");

        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        boolean successful =
                authService.login(
                        username,
                        password
                );

        if (successful) {

            System.out.println(
                    "Login successful!"
            );

        } else {

            System.out.println(
                    "Login failed."
            );
        }
    }
}