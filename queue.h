#include <pthread.h>

#define QUEUE_SIZE (4)
#define MAX_LEN (4)

typedef char password_t[MAX_LEN + 1];

typedef struct task_t {
  password_t password;
} task_t;

typedef struct queue_t {
  task_t queue[QUEUE_SIZE];
  int head;
  int tail;
  pthread_mutex_t head_mutex;
  pthread_mutex_t tail_mutex;
  sem_t empty;
  sem_t full;
} queue_t;

void queue_init (queue_t * q)
{
  q->head = 0;
  q->tail = 0;
  pthread_mutex_init (&q->head_mutex, NULL);
  pthread_mutex_init (&q->tail_mutex, NULL);
  sem_init (&q->empty, 0, QUEUE_SIZE);
  sem_init (&q->full, 0, 0);
}

void queue_push (queue_t * q, task_t * task)
{
  sem_wait (&q->empty);
  pthread_mutex_lock (&q->tail_mutex);
  q->queue[q->tail] = *task;
  if (++q->tail == sizeof (q->queue) / sizeof (q->queue[0]))
    q->tail = 0;
  pthread_mutex_unlock (&q->tail_mutex);
  sem_post (&q->full);
}

void queue_pop (queue_t * q, task_t * task)
{
  sem_wait (&q->full);
  pthread_mutex_lock (&q->head_mutex);
  *task = q->queue[q->head];
  if (++q->head == sizeof (q->queue) / sizeof (q->queue[0]))
    q->head = 0;
  pthread_mutex_unlock (&q->head_mutex);
  sem_post (&q->empty);
}
