#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <crypt.h>

#define MAX_LEN 16

bool brute_iter (char * alph, char * hash, int pass_len)
{
  char __attribute__ ((unused)) password[MAX_LEN + 1];
  int alph_len_m1 = strlen (alph) - 1;
  int pos[MAX_LEN];
  int j;

  password[pass_len] = 0;

  for (j = 0; j < pass_len; ++j)
    {
      password[j] = alph[0];
      pos[j] = 0;
    }
  
  while (true)
    {
      char *myhash = crypt (password, hash);
      if (strcmp(myhash, hash) == 0) 
	{
	  printf("%s\n", password);
	  return true;
	}
     
      //идем с конца и все 9ки заменяем на 0, (если вышли за границу то выход) первую не 9ку увеличиваем на 1
      for (j = pass_len - 1; (j >= 0) && (pos[j] == alph_len_m1); j--)
	{
	  pos[j] = 0;
	  password[j] = alph[0];
	}
      if (j < 0)
	{
	  if (strcmp(crypt (password, hash), hash) == 0) 
	    {
	      printf("%s\n", password);
	      return true;
	    }
	  else return false;
	}
      password[j] = alph[++pos[j]];
    }
}

void brute_rec (char * alph)
{
  char __attribute__ ((unused)) password[MAX_LEN + 1];
  int alph_len = strlen (alph);
 
  void rec (int pos)
  {
    if (pos == MAX_LEN) { 
      //printf ("%s\n", password);
      return;
    }
    int i;
    for (i = 0; i < alph_len; i++) 
      {
	password[pos] = alph[i];
	rec (pos + 1);
      }
  }

  password[MAX_LEN] = 0;
  rec (0);
}

void brute_all (char *hash)
{
  char alph[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*.";
  int i = 3;
  bool pass = false;
  while(!pass && i <= MAX_LEN)
    {
      pass = brute_iter (alph, hash, i);
      i++;
    }
}

int main (int argc, char * argv[]) 
{
  char *hash = argv[1];
  brute_all(hash);
  
  return (EXIT_SUCCESS);
}
