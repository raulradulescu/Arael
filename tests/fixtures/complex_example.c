#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Struct definition
typedef struct {
    int id;
    char name[32];
    float score;
} Student;

// Global variables
static int global_counter = 0;
const char* program_name = "ComplexExample";

// Function prototypes
void print_banner(void);
int fibonacci(int n);
void process_student(Student* s);
char* encode_string(const char* input);
int validate_password(const char* password);

// Main function
int main(int argc, char** argv) {
    print_banner();

    // Array of strings
    const char* messages[] = {
        "Initializing system...",
        "Loading configuration...",
        "Ready to process data",
        NULL
    };

    // Print messages
    for (int i = 0; messages[i] != NULL; i++) {
        printf("[%d] %s\n", i, messages[i]);
        global_counter++;
    }

    // Test fibonacci
    printf("\nFibonacci sequence:\n");
    for (int i = 0; i < 10; i++) {
        printf("fib(%d) = %d\n", i, fibonacci(i));
    }

    // Test student processing
    Student alice = {1, "Alice", 95.5};
    Student bob = {2, "Bob", 87.3};

    printf("\nProcessing students:\n");
    process_student(&alice);
    process_student(&bob);

    // Test string encoding
    const char* secret = "FLAG{test_secret_123}";
    char* encoded = encode_string(secret);
    printf("\nEncoded secret: %s\n", encoded);
    free(encoded);

    // Test password validation
    const char* passwords[] = {
        "password123",
        "admin",
        "super_secret_password",
        NULL
    };

    printf("\nValidating passwords:\n");
    for (int i = 0; passwords[i] != NULL; i++) {
        int valid = validate_password(passwords[i]);
        printf("Password '%s': %s\n", passwords[i],
               valid ? "VALID" : "INVALID");
    }

    printf("\nTotal operations: %d\n", global_counter);
    return 0;
}

void print_banner(void) {
    printf("========================================\n");
    printf("  %s v1.0\n", program_name);
    printf("  Complex Analysis Test Program\n");
    printf("========================================\n\n");
}

int fibonacci(int n) {
    if (n <= 1) {
        return n;
    }
    return fibonacci(n - 1) + fibonacci(n - 2);
}

void process_student(Student* s) {
    if (s == NULL) {
        fprintf(stderr, "Error: NULL student pointer\n");
        return;
    }

    printf("Student #%d: %s (Score: %.1f)\n", s->id, s->name, s->score);

    // Grade assignment
    char grade;
    if (s->score >= 90) {
        grade = 'A';
    } else if (s->score >= 80) {
        grade = 'B';
    } else if (s->score >= 70) {
        grade = 'C';
    } else if (s->score >= 60) {
        grade = 'D';
    } else {
        grade = 'F';
    }

    printf("  Grade: %c\n", grade);
    global_counter++;
}

char* encode_string(const char* input) {
    if (input == NULL) {
        return NULL;
    }

    size_t len = strlen(input);
    char* output = (char*)malloc(len + 1);

    if (output == NULL) {
        return NULL;
    }

    // Simple XOR encoding with key 0x42
    for (size_t i = 0; i < len; i++) {
        output[i] = input[i] ^ 0x42;
    }
    output[len] = '\0';

    global_counter++;
    return output;
}

int validate_password(const char* password) {
    if (password == NULL) {
        return 0;
    }

    // Check length
    size_t len = strlen(password);
    if (len < 8 || len > 32) {
        return 0;
    }

    // Check for required characters
    int has_digit = 0;
    int has_lower = 0;
    int has_upper = 0;

    for (size_t i = 0; i < len; i++) {
        if (password[i] >= '0' && password[i] <= '9') {
            has_digit = 1;
        } else if (password[i] >= 'a' && password[i] <= 'z') {
            has_lower = 1;
        } else if (password[i] >= 'A' && password[i] <= 'Z') {
            has_upper = 1;
        }
    }

    // Simple password check
    if (strcmp(password, "super_secret_password") == 0) {
        return 1;
    }

    global_counter++;
    return has_digit && has_lower && has_upper;
}
