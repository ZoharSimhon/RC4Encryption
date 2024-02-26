#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/sysinfo.h> // For getting the number of available CPUs
#include <ctype.h>

#define MAX_QUEUE_SIZE 5000
#define NUM_THREADS (get_nprocs() * 2) // Utilize available CPUs effectively
#define KEY_LENGTH 4

// Structure for a circular queue
typedef struct
{
    long *queue;              // Array to hold the queue elements
    char *ciphertext;         // Ciphertext to be decrypted
    int key_length;           // Length of the encryption key
    int ciphertext_length;    // Length of the ciphertext
    int front, rear, size;    // Queue pointers and size
    pthread_mutex_t lock;     // Mutex for thread safety
    pthread_cond_t not_empty; // Condition variable for non-empty queue
    pthread_cond_t not_full;  // Condition variable for non-full queue
} CircularQueue;

// Structure for a thread pool
typedef struct
{
    pthread_t *threads;   // Array to hold thread identifiers
    int num_threads;      // Number of threads in the pool
    CircularQueue *queue; // Pointer to the shared circular queue
    long checked_keys;    // Counter for the number of checked keys
    pthread_mutex_t lock; // Mutex for thread pool management
} ThreadPool;

// Function to swap two elements
void swap(unsigned char *a, unsigned char *b)
{
    unsigned char temp = *a;
    *a = *b;
    *b = temp;
}

// Function to initialize the RC4 S-box
void initialize_sbox(unsigned char *sbox, const unsigned char *key, size_t key_length)
{
    for (int i = 0; i < 256; i++)
    {
        sbox[i] = (unsigned char)i;
    }

    int j = 0;
    for (int i = 0; i < 256; i++)
    {
        j = (j + sbox[i] + key[i % key_length]) % 256;
        swap(&sbox[i], &sbox[j]);
    }
}

// Function to perform RC4 decryption
void rc4_decrypt(const unsigned char *input, size_t input_length, const unsigned char *key, size_t key_length, unsigned char *output)
{
    unsigned char sbox[256];
    initialize_sbox(sbox, key, key_length);

    int i = 0;
    int j = 0;

    for (size_t k = 0; k < input_length; k++)
    {
        i = (i + 1) % 256;
        j = (j + sbox[i]) % 256;
        swap(&sbox[i], &sbox[j]);

        int t = (sbox[i] + sbox[j]) % 256;
        output[k] = input[k] ^ sbox[t];
    }
}

// Function to convert a long integer to base-256 representation
void longToBase256(long num, unsigned char result[])
{
    long i = 0;

    // Continue until the number becomes zero
    while (num > 0)
    {
        // Extract the remainder when divided by 256
        result[i] = num % 256;

        // Divide the number by 256
        num /= 256;

        // Move to the next position in the result array
        i++;
    }
}

// Function to initialize a circular queue
void initializeQueue(CircularQueue *q)
{
    q->queue = (long *)malloc(MAX_QUEUE_SIZE * sizeof(long));
    q->front = q->rear = -1;
    q->size = 0;
    pthread_mutex_init(&q->lock, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

// Function to check if a circular queue is empty
bool isQueueEmpty(CircularQueue *q)
{
    return (q->size == 0);
}

// Function to check if a circular queue is full
bool isQueueFull(CircularQueue *q)
{
    return (q->size == MAX_QUEUE_SIZE);
}

// Function to enqueue an item into the circular queue
void enqueue(CircularQueue *q, long item)
{
    pthread_mutex_lock(&q->lock);
    while (isQueueFull(q))
    {
        pthread_cond_wait(&q->not_full, &q->lock);
    }
    if (q->front == -1)
    {
        q->front = 0;
    }
    q->rear = (q->rear + 1) % MAX_QUEUE_SIZE;
    q->queue[q->rear] = item;
    q->size++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->lock);
}

// Function to dequeue an item from the circular queue
long dequeue(CircularQueue *q)
{
    pthread_mutex_lock(&q->lock);
    while (isQueueEmpty(q))
    {
        pthread_cond_wait(&q->not_empty, &q->lock);
    }
    long item = q->queue[q->front];
    if (q->front == q->rear)
    {
        q->front = q->rear = -1;
    }
    else
    {
        q->front = (q->front + 1) % MAX_QUEUE_SIZE;
    }
    q->size--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->lock);
    return item;
}

// Function to check if a plaintext is valid (contains only printable characters)
int is_valid_plaintext(const char *text, int len)
{
    for (int i = 0; i < len; i++)
    {
        if (!isprint(text[i]))
        {
            return 0; // Non-printable character found
        }
    }
    return 1; // All characters are printable
}

// Function executed by each thread in the pool
void *processNumbers(void *arg)
{
    // Cast the input argument back to ThreadPool type
    ThreadPool *pool = (ThreadPool *)arg;
    // Access the CircularQueue from the ThreadPool
    CircularQueue *queue = pool->queue;
    long num;

    // Allocate memory for the decrypted text
    unsigned char *decrypted_text = malloc(100);
    decrypted_text[99] = '\0'; // Null-terminate the string

    // Assuming the maximum length of the base-256 representation is 4 bytes
    unsigned char result[queue->key_length];
    char key[queue->key_length + 1];

    // Infinite loop to continuously process numbers
    while (true)
    {
        // Dequeue a number from the circular queue
        num = dequeue(queue);

        // Check if there are no more numbers to process
        if (num == -1)
        {
            // Free memory and exit the thread
            free(decrypted_text);
            break; // No more numbers to process
        }

        // Convert the number to base-256 representation
        longToBase256(num, result);

        // Create a key from the base-256 representation
        for (int i = queue->key_length - 1; i >= 0; i--)
        {
            key[i] = result[i];
        }
        key[queue->key_length] = 0; // Null-terminate the key string

        // Decrypt the ciphertext using RC4 algorithm
        rc4_decrypt((const unsigned char *)queue->ciphertext, queue->ciphertext_length, key, queue->key_length, decrypted_text);

        // Check if the decrypted text is a valid printable string
        if (is_valid_plaintext(decrypted_text, queue->ciphertext_length))
            printf("Decrypted text is: %s\n", decrypted_text);

        // Reset decrypted_text for the next iteration
        memset(decrypted_text, 0, queue->ciphertext_length + 1);

        // Increment the count of checked keys and print progress
        pthread_mutex_lock(&pool->lock);
        pool->checked_keys++;
        if (pool->checked_keys % 400000000 == 0)
        {
            printf("We have already checked %ld keys.\n", pool->checked_keys);
        }
        pthread_mutex_unlock(&pool->lock);
    }

    // Exit the thread
    pthread_exit(NULL);
}

// Function to create a thread pool
void createThreadPool(ThreadPool *pool, CircularQueue *queue)
{
    pool->threads = (pthread_t *)malloc(NUM_THREADS * sizeof(pthread_t));
    pool->num_threads = NUM_THREADS;
    pool->queue = queue;
    pool->checked_keys = 0;
    pthread_mutex_init(&pool->lock, NULL);

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_create(&pool->threads[i], NULL, processNumbers, pool);
    }
}

// Function to wait for all threads in the pool to finish
void joinThreadPool(ThreadPool *pool)
{
    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(pool->threads[i], NULL);
    }
}

// Function to destroy a thread pool and free resources
void destroyThreadPool(ThreadPool *pool)
{
    pthread_cond_destroy(&pool->queue->not_empty);
    pthread_cond_destroy(&pool->queue->not_full);
    pthread_mutex_destroy(&pool->queue->lock);
    free(pool->queue->queue);
    pthread_mutex_destroy(&pool->lock);
    free(pool->threads);
}

int main()
{
    // Read ciphertext from standard input
    char ciphertext[200];
    int d;
    int i;
    for (i = 0; (scanf("%d", &d)) != EOF; i++)
    {
        ciphertext[i] = d;
    }
    printf("%s\n", ciphertext);

    // Initialize CircularQueue and ThreadPool accordig to the given cipher text
    CircularQueue queue;
    initializeQueue(&queue);
    ThreadPool pool;
    createThreadPool(&pool, &queue);
    queue.ciphertext = ciphertext;
    queue.ciphertext_length = i;
    queue.key_length = KEY_LENGTH;

    // Enqueue numbers into the circular queue for processing
    int bits = 8*KEY_LENGTH;
    long limit = pow(2,bits);
    for (long num = 0; num < limit; ++num)
    {
        enqueue(&queue, num);
    }

    // Signal threads that there are no more numbers to process
    for (int i = 0; i < NUM_THREADS; i++)
    {
        enqueue(&queue, -1);
    }

    // Wait for all threads to finish
    joinThreadPool(&pool);

    // Destroy the thread pool and free resources
    destroyThreadPool(&pool);

    return 0;
}