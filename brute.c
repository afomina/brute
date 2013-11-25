#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#define __USE_GNU
#include <crypt.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <regex.h>
#include "queue.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ALPH "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define PORT 1234
#define MAX_CON 10
#define SERVER_IP INADDR_LOOPBACK

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
  struct in_addr server_addr;
} config_t;


typedef bool (* handler_t) (config_t *, task_t *, struct crypt_data *);
typedef int (* brute_t) (config_t *, int, handler_t, struct crypt_data *);
typedef void * (* func) (void *);

typedef struct brute_data {
  config_t * conf;
  handler_t handler;
  struct crypt_data * crypt;
} brute_data;

int get_proc_amount() {
  FILE * file = fopen("/proc/cpuinfo", "r");
  regex_t regex;
  if (regcomp(&regex, "processor.*([0-9])", REG_EXTENDED)) {
    fprintf(stderr, "Regex error\n");
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

bool check_password (config_t * config, task_t * task, struct crypt_data * data)
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

bool push_password (config_t * config, task_t * task, struct crypt_data * data)
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

bool brute_rec (config_t * config, int pass_len, handler_t handler, struct crypt_data * data)
{
  task_t task;
  int alph_len = strlen (config->alph);

  bool rec (int pos)
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

void * thread_brute (void * arg) {
  brute_data * data = (brute_data *) arg;
  brute_all(data->conf, data->handler, data->crypt);
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

void server (config_t * conf) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    fprintf(stderr, "Socket error\n");
    return;
  }
  struct socaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sock, (struct socaddr *) &addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Bind error\n");
    return;
  }
  
  pthread_t th;
  brute_data data = {
    .conf = conf,
    .handler = push_password,
    .crypt = NULL
  };
  pthread_create(&th, NULL, &thread_brute, &data);
  listen(sock, MAX_CON);
  task_t task;
  bool found;
  while (true) {
    int client = accept(sock, NULL, NULL);
    queue_pop(&conf->q, &task);
    send(client, &task, sizeof(task), 0);
    recv(client, &found, sizeof(found), 0);
    if (found) {
      strcpy(conf->password, task.password); 
      break;
    }
  } 
  close(sock);
}

void brute_client (config_t * conf) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    fprintf(stderr, "Socket error\n");
    return;
  }
  struct socaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  addr.sin_addr.s_addr = conf->server_addr;
  if (connect(sock, (struct socaddr *) &addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Connect error\n");
    return;
  }
  task_t task;
  while (true) {
    recv(sock, &task, sizeof(task), 0);
    bool status = check_password(conf, &task, NULL);
    send(sock, &status, sizeof(status), 0);  
    if (status)
      break;
  }
  close(sock);
}

void parse_params (config_t * config, int argc, char * argv[])
{
  int opt;
  while ((opt = getopt(argc, argv, "irh:n:a:1mc:s")) != -1)
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
      case '1':
        config->run_mode = RM_SINGLE;
        break;
      case 'm':
        config->run_mode = RM_MULTI;
        break;
      case 's':
        config->run_mode = RM_SERVER;
        break;
      case 'c':
        config->run_mode = RM_CLIENT;
        inet_aton(optarg, &config->server_addr);
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
    case RM_SERVER:
      server(&config);
      break;
    case RM_CLIENT:
      brute_client(&config);
      break;
  }
  if (config.found)
    printf("Password '%s'\n", config.password);
  else
    printf("Password not found\n");

  return (EXIT_SUCCESS);
}
