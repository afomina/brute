#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

#define MAX_LEN (4)
#define QUEUE_SIZE (4)
#define ALPH "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define THREAD_N (4)

typedef char password_t[MAX_LEN + 1];

typedef struct task_t {
	password_t pass;
} task_t;

typedef enum {
  BM_ITER,
  BM_REC,
} brute_mode_t;

typedef enum {
  RM_SINGLE,
  RM_MULTI,
} run_mode_t;

typedef struct queue_t {
  password_t queue[QUEUE_SIZE];
  int head;
  int tail;
  pthread_mutex_t head_mutex;
  pthread_mutex_t tail_mutex;
  sem_t empty;
  sem_t full;
} queue_t;

typedef struct config_t {
  brute_mode_t brute_mode;
  run_mode_t run_mode;
  char * hash;
  int max_n;
  char * alph;
  bool found;
  queue_t q;
} config_t;

typedef int (*handler_t) (config_t *, password_t);
typedef int (*brute) (config_t *, int, handler_t);

typedef void * (* func) (void *);

void queue_init (queue_t * q)
{
  q->head = 0;
  q->tail = 0;
  pthread_mutex_init (&q->head_mutex, NULL);
  pthread_mutex_init (&q->tail_mutex, NULL);
  sem_init (&q->empty, 0, QUEUE_SIZE);
  sem_init (&q->full, 0, 0);
}

void queue_push (queue_t * q, task_t task)
{
  sem_wait (&q->empty);
  pthread_mutex_lock (&q->tail_mutex);
  q->queue[q->tail] = task_t;
  if (++q->tail == sizeof (q->queue) / sizeof (q->queue[0]))
    q->tail = 0;
  pthread_mutex_unlock (&q->tail_mutex);
  sem_post (&q->full);
}

void queue_pop (queue_t * q, task_t task)
{
  sem_wait (&q->full);
  pthread_mutex_lock (&q->head_mutex);
  task = q->queue[q->head];
  if (++q->head == sizeof (q->queue) / sizeof (q->queue[0]))
    q->head = 0;
  pthread_mutex_unlock (&q->head_mutex);
  sem_post (&q->empty);
}

int check_password (config_t * config, password_t password)
{
  int status = !strcmp (crypt (password, config->hash), config->hash);
  if (status)
    {
      printf ("password = '%s'\n", password);
      config->found = true;
    }
  return status;
}

int push_password (config_t * config, task_t task)
{
  queue_push(&config->q, task);
  return 0;
}

void * consumer(void * args) {

}

void brute_multi (config_t * config) {
	pthread_t threads[THREAD_N];
	int i;
	for (i = 0; i < THREAD_N; i++) {
		pthread_create(&threads[i], NULL, &consumer, config);
	}
}

int brute_iter (config_t * config, int pass_len, handler_t handler)
{
  password_t password;
  int alph_len_m1 = strlen (config->alph) - 1;
  int pos[MAX_LEN];
  int j;

  password[pass_len] = 0;

  for (j = 0; j < pass_len; ++j)
    {
      password[j] = config->alph[0];
      pos[j] = 0;
    }
  
  while (true)
    {           
      if (handler (config, password))
	return 1;
      //идем с конца и все 9ки заменяем на 0, (если вышли за границу то выход) первую не 9ку увеличиваем на 1
      for (j = pass_len - 1; (j >= 0) && (pos[j] == alph_len_m1); j--)
	{
	  pos[j] = 0;
	  password[j] = config->alph[0];
	}
      if (j < 0)
	{
	  return 0;
	}

      password[j] = config->alph[++pos[j]];
    }
}

void * brute_rec (config_t * config, int pass_len, handler_t handler)
{
  password_t password;
  int alph_len = strlen (config->alph);

  void rec (int pos)
  {
    if (config->found) return;
    if (pos == pass_len) { 
      handler (config, password);
      return;
    }
    int i;
    for (i = 0; i < alph_len; i++) 
      {
	password[pos] = config->alph[i];
	rec (pos + 1);
      }
  }

  password[pass_len] = 0;
  rec (0);
}

void multi_thread_brute (func f, void * arg)
{
  pthread_t thread;
  pthread_create (&thread, NULL, f, arg);
}

handler_t run_mode_selector (config_t * config)
{
  switch (config->run_mode)
    {
    case RM_SINGLE:
      return check_password;
    case RM_MULTI:      
      return push_password;
    }
}

brute brute_selector (config_t * config)
{
  switch (config->brute_mode)
    {
    case BM_ITER:
       return brute_iter;
    case BM_REC:
	return brute_rec;
    }
}

void brute_all (config_t * config)
{
  brute func = brute_selector(config);
  handler_t handler = run_mode_selector(config);
  int i;
  for (i = 0; i <= config->max_n; ++i)
    {
      func(config, i, handler);
      if (config->found) 
	return;
    }
  if (!config->found)
    printf("Password not found");
}

void parse_params (config_t * config, int argc, char * argv[])
{
  int opt;
  while ((opt = getopt(argc, argv, "irh:n:a:sm")) != -1)
    {
      switch (opt)
	{
	case 'i':
	  config->brute_mode = BM_ITER;
	  break;
	case 'r':
	  config->brute_mode = BM_REC;
	  break;
	case 'h': 
	  config->hash = optarg; 
	  break;
	case 'n': 
	  config->max_n = atoi (optarg); 
	  break;
	case 'a':
	  config->alph = optarg;
	  break;
	case 's':
	  config->run_mode = RM_SINGLE;
	  break;
	case 'm':
	  config->run_mode = RM_MULTI;
	  break;
	}
    }
}

int main (int argc, char * argv[]) 
{
  config_t config = {
    .brute_mode = BM_ITER,
    .run_mode = RM_SINGLE,
    .hash = NULL,
    .max_n = MAX_LEN,
    .alph = ALPH; 
  };

  parse_params (&config, argc, argv);

  if (config.run_mode == RM_MULTI)
  {
    queue_init (&config.q);
  }

  if (NULL == config.hash)
    {
      fprintf (stderr, "Hash missed!\n");
      return (EXIT_FAILURE);
    }

  brute_all (&config);

  return (EXIT_SUCCESS);
}
