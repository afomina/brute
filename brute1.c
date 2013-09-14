#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_LEN (4)

typedef char password_t[MAX_LEN + 1];

typedef enum {
  BM_ITER,
  BM_REC,
} brute_mode_t;

typedef enum {
  RM_SINGLE,
  RM_MULTI,
} run_mode_t;

typedef struct buffer {
  password_t pool[MAX_LEN];
  int head;
  int tail;
} buffer;

typedef struct config_t {
  brute_mode_t brute_mode;
  run_mode_t run_mode;
  char * hash;
  int max_n;
  char * alph;
  bool found;
} config_t;

typedef int (*handler_t) (config_t *, password_t);

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

int push_password (config_t * config, password_t password)
{
  
}

void brute_iter (config_t * config, int pass_len, handler_t handler)
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

void brute_rec (config_t * config, int pass_len, handler_t handler)
{
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

void brute_selector (config_t * config, int pass_len)
{
  switch (config->brute_mode)
    {
    case BM_ITER:
      brute_iter(config, pass_len, run_mode_selector (config));
      break;
    case BM_REC:
      brute_rec(config, pass_len, run_mode_selector (config));
    }
}

void brute_all (config_t * config)
{
  int i;
  for (i = 0; i <= config->max_n; ++i)
    brute_selector (config, i);
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
    .alph = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  };

  parse_params (&config, argc, argv);
  if (NULL == config.hash)
    {
      fprintf (stderr, "Hash missed!\n");
      return (EXIT_FAILURE);
    }

  brute_all (&config);
  
  return (EXIT_SUCCESS);
}