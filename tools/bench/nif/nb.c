#include <erl_nif.h>
static ERL_NIF_TERM noop(ErlNifEnv* e,int c,const ERL_NIF_TERM a[]){ return a[0]; }
static ERL_NIF_TERM add(ErlNifEnv* e,int c,const ERL_NIF_TERM a[]){ long x,y; enif_get_long(e,a[0],&x); enif_get_long(e,a[1],&y); return enif_make_long(e,x+y); }
static ERL_NIF_TERM bsum(ErlNifEnv* e,int c,const ERL_NIF_TERM a[]){ ErlNifBinary b; enif_inspect_binary(e,a[0],&b); unsigned long s=0; for(size_t i=0;i<b.size;i++) s+=b.data[i]; return enif_make_ulong(e,s); }
static ERL_NIF_TERM lsum(ErlNifEnv* e,int c,const ERL_NIF_TERM a[]){ ERL_NIF_TERM h,t=a[0],l; long s=0,x; while(enif_get_list_cell(e,t,&h,&l)){ enif_get_long(e,h,&x); s+=x; t=l;} return enif_make_long(e,s); }
static ErlNifFunc f[]={{"noop",1,noop,0},{"add",2,add,0},{"bsum",1,bsum,0},{"lsum",1,lsum,0},{"dnoop",1,noop,ERL_NIF_DIRTY_JOB_CPU_BOUND}};
ERL_NIF_INIT(nb,f,0,0,0,0)
