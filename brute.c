#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#define __USE_GNU
#include <crypt.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <regex.h>
#include "queue.h"

#define ALPH "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

typedef enum {
  BM_ITER,
  BM_REC,
} brute_mode_t;

typedef enum {
  RM_SINGLE,
  RM_MULTI,
  RM_SERVER,
  RM_CLIENT,
} run_mode_t;

typedef struct config_t {
  brute_mode_t brute_mode;
  run_mode_t run_mode;
  char * hash;
  int max_n;
  char * alph;
  bool found;
  password_t password;
  queue_t q;
} config_t;

typedef int (*handler_t) (config_t *, task_t *, struct crypt_data *);
typedef int (*brute_t) (config_t *, int, handler_t, struct crypt_data *);

typedef void * (* func) (void *);

int check_password (config_t * config, task_t * task, struct crypt_data * data)
{
  char * hashed_pass = crypt_r (task->password, config->hash, data);
  int status = !strcmp (hashed_pass, config->hash);
  if (status)
  {
    strcpy (config->password, task->password);
    config->found = true;
  }
  return status;
}

int push_password (config_t * config, task_t * task, struct crypt_data * data)
{
  queue_push(&config->q, task);
  return config->found;
}

bool brute_iter (config_t * config, int pass_len, handler_t handler, struct crypt_data * data)
{
  task_t task;
  int alph_len_m1 = strlen (config->alph) - 1;
  int pos[MAX_LEN];
  int j;

  task.password[pass_len] = 0;

  for (j = 0; j < pass_len; ++j)
  {
    task.password[j] = config->alph[0];
    pos[j] = 0;
  }

  while (true)
  {           
    if (handler (config, &task, data))
      return true;
    //идем с конца и все 9ки заменяем на 0, (если вышли за границу то выход) первую не 9ку увеличиваем на 1
    for (j = pass_len - 1; (j >= 0) && (pos[j] == alph_len_m1); j--)
    {
      pos[j] = 0;
      task.password[j] = config->alph[0];
    }
    if (j < 0)
      break;
    task.password[j] = config->alph[++pos[j]];
  }
  return 0;
}

int brute_rec (config_t * config, int pass_len, handler_t handler, struct crypt_data * data)
{
  task_t task;
  int alph_len = strlen (config->alph);

  int rec (int pos)
  {
    if (pos == pass_len) { 
      return handler (config, &task, data);
    }
    int i;
    for (i = 0; i < alph_len; i++) 
    {
      task.password[pos] = config->alph[i];
      if (rec (pos + 1))
        return true;
    }
    return false;
  }

  task.password[pass_len] = 0;
  return rec (0);
}

brute_t brute_selector (config_t * config)
{
  switch (config->brute_mode)
  {
    case BM_ITER:
      return brute_iter;
    case BM_REC:
      return brute_rec;
  }
  return NULL;
}

void brute_all (config_t * config, handler_t handler, struct crypt_data * data)
{
  brute_t brute = brute_selector(config);
  int i;

  for (i = 1; i <= config->max_n; ++i)
  {
    if (brute(config, i, handler, data))
      break;
  }
}

void * consumer(void * args) {
  struct crypt_data data;
  data.initialized = 0;
  config_t * config = (config_t *) args;
  task_t task;
  while (true) {
    queue_pop(&config->q, &task);
    if (check_password(config, &task, &data))
      break;
  } 
  return NULL;
}

int get_proc_amount() {
  FILE * file = fopen("/proc/cpuinfo", "r");
  regex_t regex;
  if (regcomp(&regex, "processor.*([0-9])", REG_EXTENDED)) {
    printf("Regex error\n");
    return EXIT_FAILURE;
  }
  regmatch_t pmatch[2];
  char s[300];
  int n = 0;
  while (fgets(s, sizeof(s), file)) {
    if (!regexec(&regex, s, 2, pmatch, 0)) {
      n = atoi(&(s[pmatch[1].rm_so]));
    }
  }
  fclose(file);
  return n + 1;
}

void brute_multi (config_t * config) {
  int n = get_proc_amount() + 1;
  pthread_t threads[n];
  queue_init (&config->q);
  int i;
  for (i = 0; i < n; i++) {
    pthread_create(&threads[i], NULL, &consumer, config);
  }
  brute_all(config, push_password, NULL);
}

void brute_single (config_t * config) {
  struct crypt_data data;
  data.initialized = 0;    
  brute_all(config, check_password, &data);
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
    .alph = ALPH
  };

  parse_params (&config, argc, argv);

  if (NULL == config.hash)
  {
    fprintf (stderr, "Hash missed!\n");
    return (EXIT_FAILURE);
  }

  switch (config.run_mode)
  {
    case RM_MULTI:
      brute_multi(&config);
      break;
    case RM_SINGLE:
      brute_single(&config);
      break;
  }
  if (config.found)
    printf("Password '%s'\n", config.password);
  else
    printf("Password not found\n");

  return (EXIT_SUCCESS);
}
