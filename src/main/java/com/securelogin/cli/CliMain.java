package com.securelogin.cli;

import com.securelogin.authentication.AuthService;
import com.securelogin.authentication.UserDatabase;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Scanner;

public final class CliMain {

    public static void main(String[] args) throws Exception {
        Files.createDirectories(Path.of("data"));

        try (UserDatabase database = new UserDatabase("jdbc:h2:./data/login;AUTO_SERVER=TRUE")) {
            database.initSchema();
            AuthService authService = new AuthService(database);
            Scanner scanner = new Scanner(System.in);

            System.out.println("Login demo -- commands: register, login, exit");
            boolean running = true;
            while (running) {
                System.out.print("\n> ");
                if (!scanner.hasNextLine()) {
                    break;
                }
                String command = scanner.nextLine().strip().toLowerCase();

                if (command.equals("register")) {
                    handleRegister(scanner, authService);
                } else if (command.equals("login")) {
                    handleLogin(scanner, authService);
                } else if (command.equals("exit") || command.equals("quit")) {
                    running = false;
                } else {
                    System.out.println("Unknown command. Use: register, login, exit");
                }
            }
        }
    }

    private static void handleRegister(Scanner scanner, AuthService authService) {
        System.out.print("Username: ");
        String username = scanner.nextLine().strip();
        char[] password = readPassword(scanner, "Password: ");
        try {
            AuthService.Result result = authService.register(username, password);
            printResult(result);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void handleLogin(Scanner scanner, AuthService authService) {
        System.out.print("Username: ");
        String username = scanner.nextLine().strip();
        char[] password = readPassword(scanner, "Password: ");
        try {
            AuthService.Result result = authService.login(username, password);
            printResult(result);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static void printResult(AuthService.Result result) {
        if (result.success()) {
            System.out.println("OK: " + result.message());
        } else {
            System.out.println("ERROR: " + result.message());
        }
    }

    private static char[] readPassword(Scanner scanner, String prompt) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }
        System.out.print(prompt + "(visible - no console attached) ");
        return scanner.nextLine().toCharArray();
    }
}
