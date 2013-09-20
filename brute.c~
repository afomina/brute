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

typedef char password_t[MAX_LEN + 1];

typedef enum {
  BM_ITER,
  BM_REC,
} brute_mode_t;

typedef enum {
  RM_SINGLE,
  RM_MULTI,
} run_mode_t;

typedef struct queue_t {
  password_t * queue[QUEUE_SIZE];
  int head;
  int tail;
  pthread_mutex_t * head_mutex;
  pthread_mutex_t * tail_mutex;
  sem_t * empty;
  sem_t * full;
} queue_t;

void init (queue_t * q)
{
  q->head = 0;
  q->tail = 0;
  pthread_mutex_init (q->head_mutex, NULL);
  pthread_mutex_init (q->tail_mutex, NULL);
  sem_init (q->empty, 0, QUEUE_SIZE);
  sem_init (q->full, 0, 0);
}

void push (queue_t * q, password_t * pass)
{
  sem_wait (q->empty);
  pthread_mutex_lock (q->tail_mutex);
  q->queue[q->tail] = pass;
  q->tail++;
  pthread_mutex_unlock (q->tail_mutex);
  sem_post (q->full);
}

void pop (queue_t * q, password_t * pass)
{
  sem_wait (q->full);
  pthread_mutex_lock (q->head_mutex);
  pass = q->queue[q->head];
  q->head++;
  pthread_mutex_unlock (q->head_mutex);
  sem_post (q->empty);
}

typedef struct config_t {
  brute_mode_t brute_mode;
  run_mode_t run_mode;
  char * hash;
  int max_n;
  char * alph;
  bool found;
  queue_t * q;
} config_t;

typedef int (*handler_t) (config_t *, password_t);

typedef struct arg_t {
  config_t * config;
  int pass_len;
  handler_t handler;
} arg_t;

typedef void * (* func) (void *);

int check_password (config_t * config, password_t password)
{
  int status = !strcmp (crypt (password, config->hash), config->hash);
  if (status)
    {
      printf ("password = '%s'\n", password);
      config->found = true;
    }
  return (status);
}

int push_password (config_t * config, password_t * password)
{
  push (config->q, password);
  return 0;
}

void * pop_password (void * arg_)
{
  arg_t * arg = (arg_t *) arg_;
  config_t * config = arg->config;
  password_t password;
  pop (config->q, &password);
  check_password (config, password);
}

void * brute_iter (void * arg_)
{
  arg_t * arg = (arg_t *) arg_;
  config_t * config = arg->config;
  int pass_len = arg->pass_len;
  handler_t handler = arg->handler;

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
	return;
      //идем с конца и все 9ки заменяем на 0, (если вышли за границу то выход) первую не 9ку увеличиваем на 1
      for (j = pass_len - 1; (j >= 0) && (pos[j] == alph_len_m1); j--)
	{
	  pos[j] = 0;
	  password[j] = config->alph[0];
	}
      if (j < 0)
	break;

      password[j] = config->alph[++pos[j]];
    }
}

void * brute_rec (void * arg_)
{
  arg_t * arg = (arg_t *) arg_;
  config_t * config = arg->config;
  int pass_len = arg->pass_len;
  handler_t handler = arg->handler;

  char password[MAX_LEN + 1];
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

void run_mode_selector (config_t * config, int pass_len)
{
  arg_t * arg;
  arg->config = config;
  arg->pass_len = pass_len;

  switch (config->run_mode)
    {
    case RM_SINGLE:
      arg->handler = check_password;
      //brute_selector (arg) (arg);
      break;
    case RM_MULTI:      
      arg->handler = push_password;
      multi_thread_brute (brute_selector (arg), arg);
    }
}

int brute_selector (arg_t * arg)
{
  switch (arg->config->brute_mode)
    {
    case BM_ITER:
      return brute_iter;
    case BM_REC:
      return brute_rec;
    }
}

void brute_all (config_t * config)
{
  int i;
  for (i = 0; i <= config->max_n; ++i)
    run_mode_selector (config, i);
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
  queue_t q;
  init (&q);

  config_t config = {
    .brute_mode = BM_ITER,
    .run_mode = RM_SINGLE,
    .hash = NULL,
    .max_n = MAX_LEN,
    .alph = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    .q = &q,
  };

  parse_params (&config, argc, argv);
  if (NULL == config.hash)
    {
      fprintf (stderr, "Hash missed!\n");
      return (EXIT_FAILURE);
    }

 //brute_all (&config);

  arg_t arg;
  arg.config = &config;
  arg.pass_len = MAX_LEN;
  arg.handler = push_password;
 
  pthread_t thread1;
  pthread_create (&thread1, NULL, &brute_iter, &arg);

  pthread_t thread2;
  pthread_create (&thread2, NULL, &pop_password, &arg);
  
  return (EXIT_SUCCESS);
}
