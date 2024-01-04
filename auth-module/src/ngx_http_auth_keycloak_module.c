#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
  ngx_str_t  path;
  ngx_str_t  realm;
} ngx_http_auth_keycloak_conf_t;

typedef struct {
    ngx_uint_t                done;
    ngx_uint_t                status;
    ngx_uint_t                body_processed;
    ngx_uint_t                waiting_more_body;
    ngx_str_t                 acct_num;
    ngx_int_t                 webprice;
    ngx_http_request_t       *subrequest;
} ngx_http_auth_keycloak_ctx_t;

static ngx_int_t ngx_http_auth_keycloak_init(ngx_conf_t *cf);
static void * ngx_http_auth_keycloak_create_conf(ngx_conf_t *cf);
static char * ngx_http_auth_keycloak_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_auth_keycloak_path (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_auth_keycloak_realm (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auth_keycloak_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_keycloak_req_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
static ngx_str_t get_acct_num_from_buffer(ngx_http_request_t *r, ngx_str_t response );
static ngx_int_t get_webprice_from_buffer(ngx_http_request_t *r, ngx_str_t response );
static ngx_int_t update_request(ngx_http_request_t  *r);
static int process_acct_num_uri_request(ngx_http_request_t  *r, ngx_str_t * acctNum, ngx_int_t webprice);
static int remove_acctnum_from_args(ngx_http_request_t  *r, ngx_str_t *req_args, ngx_str_t *ret_args);
static int inject_new_args(ngx_http_request_t  *r, ngx_str_t *acct_num, ngx_int_t webprice, ngx_str_t *args);
static void process_body_request(ngx_http_request_t  *r);
static size_t get_buffer_chunk (ngx_http_request_t  *r, u_char ** chunk, ngx_chain_t  *current_chain);
static ngx_int_t compile_regex(ngx_http_request_t *r, ngx_regex_compile_t **rc, ngx_str_t pattern);
ngx_int_t create_get_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags);

static ngx_command_t ngx_http_auth_keycloak_commands[] = {

  { ngx_string("keycloak_path"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_auth_keycloak_path,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },
  { ngx_string("keycloak_realm"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_auth_keycloak_realm,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL },

  ngx_null_command
};


static ngx_http_module_t ngx_http_auth_keycloak_module_ctx = {
  NULL, /* preconfiguration */
  ngx_http_auth_keycloak_init,      /* postconfiguration */

  NULL,                        /* create main configuration */
  NULL,                        /* init main configuration */

  NULL,                        /* create server configuration */
  NULL,                        /* merge server configuration */

  ngx_http_auth_keycloak_create_conf,             /* create location configuration */
  ngx_http_auth_keycloak_merge_conf               /* merge location configuration */
};

ngx_module_t ngx_http_auth_keycloak_module = {
  NGX_MODULE_V1,
  &ngx_http_auth_keycloak_module_ctx,     /* module context */
  ngx_http_auth_keycloak_commands,        /* module directives */
  NGX_HTTP_MODULE,                   /* module type */
  NULL,                              /* init master */
  NULL,                              /* init module */
  NULL,                              /* init process */
  NULL,                              /* init thread */
  NULL,                              /* exit thread */
  NULL,                              /* exit process */
  NULL,                              /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_auth_keycloak_init(ngx_conf_t *cf)
{
  ngx_http_handler_pt        *h;
  ngx_http_core_main_conf_t  *cmcf;
  

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL)
  {
    return NGX_ERROR;
  }

  *h = ngx_http_auth_keycloak_handler;

  return NGX_OK;
}

static void * ngx_http_auth_keycloak_create_conf(ngx_conf_t *cf)
{
  ngx_http_auth_keycloak_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_keycloak_conf_t));
  if (conf == NULL)
  {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "Keycloak: conf==NULL");
    return NULL;
  }

  // Initialize variables
  

  return conf;
}

static char * ngx_http_auth_keycloak_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
  ngx_http_auth_keycloak_conf_t *prev = parent;
  ngx_http_auth_keycloak_conf_t *conf = child;

  ngx_conf_merge_str_value(conf->path, prev->path, NULL);
  ngx_conf_merge_str_value(conf->realm, prev->realm, NULL);

  return NGX_CONF_OK;
}

static char *ngx_http_auth_keycloak_path (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_keycloak_conf_t *akcf = conf;

    ngx_str_t  *value;

    if (akcf->path.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    akcf->path = value[1];

    return NGX_CONF_OK;
}

static char *ngx_http_auth_keycloak_realm (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_keycloak_conf_t *akcf = conf;

    ngx_str_t  *value;

    if (akcf->realm.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    akcf->realm = value[1];

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_auth_keycloak_handler(ngx_http_request_t *r)
{

  ngx_http_auth_keycloak_conf_t *akcf;
  ngx_http_auth_keycloak_ctx_t  *ctx;
  ngx_http_post_subrequest_t    *ps;
  ngx_http_request_t            *sr;
  

  akcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_keycloak_module);

  if(akcf->path.data == NULL || akcf->realm.data == NULL){
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Keycloak: declined");
    return NGX_DECLINED;
  }

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "keycloak auth request handler");

  ctx = ngx_http_get_module_ctx(r, ngx_http_auth_keycloak_module);
  
  if (ctx != NULL) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Keycloak: ctx exist");
        if (!ctx->done) {
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: subrequest not done!");
            return NGX_AGAIN;
        }

        if (ctx->status >= NGX_HTTP_OK && ctx->status < NGX_HTTP_SPECIAL_RESPONSE)
        {
            if(ctx->body_processed == NGX_OK)
            {
              ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: body processed!");
              return NGX_OK;
            }
            return update_request(r);
        }

        if (ctx->status == NGX_HTTP_UNAUTHORIZED || ctx->status == NGX_HTTP_FORBIDDEN) {
          return ctx->status;
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "auth request unexpected status: %d", ctx->status);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_keycloak_ctx_t));
  if (ctx == NULL) {
      return NGX_ERROR;
  }

  ps = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
  if (ps == NULL) {
      return NGX_ERROR;
  }

  ps->handler = ngx_http_auth_keycloak_req_done;
  ps->data = ctx;
  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: starting subrequest!");

  // u_char mid_path = "/realms/";
  // u_char end_path = "/protocol/openid-connect/userinfo";

  // u_char complete_path = ngx_pcalloc(r->pool, akcf->path.len + 8 + akcf->realm.len + 33 + 1);
  // ngx_memcpy()

  if (create_get_subrequest(r, &akcf->path, NULL, &sr, ps,
                          NGX_HTTP_SUBREQUEST_WAITED)
      != NGX_OK)
  {
      return NGX_ERROR;
  }

  /*
    * allocate fake request body to avoid attempts to read it and to make
    * sure real body file (if already read) won't be closed by upstream
    */

  sr->request_body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
  if (sr->request_body == NULL) {
      return NGX_ERROR;
  }
  

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: after subrequest call");

  sr->header_only = 1;
  ctx->subrequest = sr;
  ctx->body_processed = NGX_AGAIN;
  ctx->waiting_more_body = 0;

  ngx_http_set_ctx(r, ctx, ngx_http_auth_keycloak_module);

  return NGX_AGAIN;

}

static ngx_int_t ngx_http_auth_keycloak_req_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_auth_keycloak_ctx_t   *ctx = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request done s:%d", r->headers_out.status);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: subrequest finished sucessfully");


    ngx_str_t response;
    response.len = r->upstream->buffer.last - r->upstream->buffer.pos;
    response.data = r->upstream->buffer.pos;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: subrequest body = %s", response.data);
    
    ngx_str_t acct_num = get_acct_num_from_buffer(r, response);
    if(acct_num.data != NULL)
    {
      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: acctNum found!");
      ctx->acct_num = acct_num;
      ngx_int_t webprice = get_webprice_from_buffer(r, response);
      ctx->webprice = webprice;
      ctx->status = NGX_HTTP_OK;
      ctx->done = 1;
      return rc;
    }

    ctx->status = NGX_HTTP_UNAUTHORIZED;
    ctx->done = 1;
    
    return rc;
}

static ngx_str_t get_acct_num_from_buffer(ngx_http_request_t *r, ngx_str_t response ){

u_char errstr[NGX_MAX_CONF_ERRSTR];
ngx_str_t err = ngx_null_string;
ngx_regex_compile_t *rc;
int captures[30];

ngx_str_t pat = ngx_string("\"acctNum\":\\s*\"([\\S]+?)\\s*\"");

if ((rc = ngx_pcalloc(r->pool, sizeof(ngx_regex_compile_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to allocate memory to compile agent patterns");
        return err;
    }

rc->pattern = pat;
rc->pool = r->pool;
rc->err.len = NGX_MAX_CONF_ERRSTR;
rc->err.data = errstr;

if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to compile regex pattern %V", rc->pattern);
        return err;
};

if (ngx_regex_exec(rc->regex, &response, captures, 30) >= 0) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: acctNum found!" );
    int cap_len = captures[3] - captures[2];
    unsigned char *capt_res = ngx_pcalloc(r->pool,cap_len+1);
    ngx_memcpy(capt_res,response.data+captures[2],cap_len);

    
    ngx_str_t acct_num;
    acct_num.data = capt_res;
    acct_num.len = cap_len;
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: found result %s",acct_num.data);
    return acct_num;
}

return err;
}

static ngx_int_t get_webprice_from_buffer(ngx_http_request_t *r, ngx_str_t response ){

u_char errstr[NGX_MAX_CONF_ERRSTR];
ngx_regex_compile_t *rc;
int captures[6];

ngx_str_t pat = ngx_string("\"showPriceInWebsite\":\\s*false");

if ((rc = ngx_pcalloc(r->pool, sizeof(ngx_regex_compile_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to allocate memory to compile agent patterns");
        return 1;
    }

rc->pattern = pat;
rc->pool = r->pool;
rc->err.len = NGX_MAX_CONF_ERRSTR;
rc->err.data = errstr;

if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to compile regex pattern %V", rc->pattern);
        return 1;
};

if (ngx_regex_exec(rc->regex, &response, captures, 6) >= 0) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: showPriceInWebsite is true!" );
    return 0;
}

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: showPriceInWebsite is false!" );
return 1;
}


static ngx_int_t update_request(ngx_http_request_t  *r){

  ngx_http_auth_keycloak_ctx_t  *ctx;
  ctx = ngx_http_get_module_ctx(r, ngx_http_auth_keycloak_module);

  if (ctx->waiting_more_body) {
      return NGX_DONE;
  }

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Keycloak: updating request");
  if(process_acct_num_uri_request(r, &ctx->acct_num, ctx->webprice) != NGX_OK){
    return NGX_ERROR;
  }
  ngx_int_t rc;
  rc = ngx_http_read_client_request_body(r, process_body_request);

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Keycloak: RC=%O",rc );

  if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
      return rc;
  }

  if (rc == NGX_AGAIN) {
      ctx->waiting_more_body = 1;
      return NGX_DONE;
  }

  r->valid_unparsed_uri = 0;

  return NGX_OK;
}

static int process_acct_num_uri_request(ngx_http_request_t  *r, ngx_str_t * acctNum, ngx_int_t webprice){

  ngx_str_t new_args;

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: Updating uri");

  new_args.data = ngx_palloc(r->pool, r->args.len);
  ngx_memcpy(new_args.data,r->args.data,r->args.len);
  new_args.len = r->args.len;

  if(r->args.len > 0) // has args
  {
    if(remove_acctnum_from_args(r,&r->args, &new_args) != NGX_OK){
        return NGX_ERROR;
    }
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: acctNum removed");
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: new args = %s", new_args.data);
  }

  if(inject_new_args(r,acctNum,webprice, &new_args) != NGX_OK){
        return NGX_ERROR;
  }

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: new args end = %s", new_args.data);
  r->args = new_args;
  return NGX_OK;
}

static int remove_acctnum_from_args(ngx_http_request_t  *r, ngx_str_t *req_args, ngx_str_t *ret_args){

    u_char errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t *rc;
    int captures[6];
    int offsetcount;
    u_char *new_args;

    ngx_str_t pat = ngx_string("(acctNum=[^&]+&?|&?acctNum=[^&]+)");

    if ((rc = ngx_pcalloc(r->pool, sizeof(ngx_regex_compile_t))) == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to allocate memory to compile agent patterns");
      return NGX_ERROR;
    }

    rc->pattern = pat;
    rc->pool = r->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    if (ngx_regex_compile(rc) != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to compile regex pattern %V", rc->pattern);
      return NGX_ERROR;
    };
    
    new_args = ngx_palloc(r->pool,req_args->len+1);
    ngx_memcpy(new_args,req_args->data,req_args->len);

    ngx_str_t new_args_parsed;
    new_args_parsed.data = new_args;
    new_args_parsed.len = req_args->len;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: req_args->len = %d", req_args->len);


    offsetcount = ngx_regex_exec(rc->regex, &new_args_parsed, captures, 50);
    while(offsetcount > 0)
    {
      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: matched");

      int cap_len = captures[3] - captures[2];
      int current_args_len = new_args_parsed.len;
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: captures[3] = %d", captures[3]);
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: current_args_len = %d", current_args_len);
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: new_args_parsed.len = %d", new_args_parsed.len);
      unsigned char *prov_args = ngx_pcalloc(r->pool,current_args_len - cap_len + 1);
      u_char *prov_args_end = ngx_copy(prov_args,new_args,captures[2]);
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: new prov args1 %s",prov_args);
      ngx_memcpy(prov_args_end,new_args + captures[3],current_args_len - captures[3]);
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: new prov args2 %s",prov_args);


      int prov_args_size = ngx_strlen(prov_args);
      new_args = ngx_pcalloc(r->pool,prov_args_size+1);
      ngx_memcpy(new_args,prov_args,prov_args_size);
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: new args = %s",new_args);

      new_args_parsed.data = new_args;
      new_args_parsed.len = prov_args_size;

      offsetcount = ngx_regex_exec(rc->regex, &new_args_parsed, captures, 6);
      
    }

    ret_args->data = new_args_parsed.data;
    ret_args->len = new_args_parsed.len;

    return NGX_OK;
}

static int inject_new_args(ngx_http_request_t  *r, ngx_str_t *acct_num, ngx_int_t webprice, ngx_str_t *args){

ngx_str_t text_to_inject;
u_char *text_to_inject_pos = NULL;
text_to_inject.len = 8+acct_num->len;

if(webprice)
  text_to_inject.len = text_to_inject.len + 24;
else
  text_to_inject.len = text_to_inject.len + 25;


text_to_inject.data = ngx_palloc(r->pool,text_to_inject.len);

text_to_inject_pos = ngx_copy(text_to_inject.data,"acctNum=",8);
text_to_inject_pos = ngx_copy(text_to_inject_pos,acct_num->data, acct_num->len);
if(webprice)
  text_to_inject_pos = ngx_copy(text_to_inject_pos,"&showPriceInWebsite=true", 24);
else
  text_to_inject_pos = ngx_copy(text_to_inject_pos,"&showPriceInWebsite=false", 25);

ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: text_to_inject = %s",text_to_inject.data);


if(args->len == 0){
  args->data = ngx_palloc(r->pool,text_to_inject.len);
  ngx_memcpy(args->data, text_to_inject.data,text_to_inject.len);
  args->len = text_to_inject.len;
}
else
{
  if(ngx_strcmp(&args->data[args->len-1],"&") == 0)
  {
    args->len = args->len-1;
  }

  ngx_str_t new_arg;
  new_arg.data = ngx_palloc(r->pool,args->len + text_to_inject.len+1);
  new_arg.len = args->len + text_to_inject.len+1;
  u_char *pt_a = ngx_copy(new_arg.data,args->data,args->len);
  u_char *pt_b = ngx_copy(pt_a,"&",1);
  ngx_memcpy(pt_b,text_to_inject.data,text_to_inject.len);

  args->data = ngx_palloc(r->pool,new_arg.len);
  ngx_memcpy(args->data, new_arg.data,new_arg.len);
  args->len = new_arg.len;
}

return NGX_OK;

}


static void process_body_request(ngx_http_request_t  *r){
  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: processing body");

  ngx_http_auth_keycloak_ctx_t  *ctx;
  ngx_buf_t                  *b;
  ngx_chain_t                out;

  ctx = ngx_http_get_module_ctx(r, ngx_http_auth_keycloak_module);

  b = ngx_calloc_buf(r->pool);
  if (b == NULL) {
      ngx_http_finalize_request(r,NGX_ERROR);
      return;
  }

  b->last_buf = 1;
  out.buf = b;
  out.next = NULL;
  


  if(r->request_body->bufs != NULL)
  {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: contains body");

    if(r->request_body->bufs->buf->in_file){
      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: body is in file");
      
      ngx_temp_file_t *tf;
      ngx_file_t *src = &r->request_body->temp_file->file;
      ngx_int_t chunk_len = 4096;

      tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
      tf->file.fd = NGX_INVALID_FILE;
      tf->file.log = r->connection->log;
      tf->path = r->request_body->temp_file->path;
      tf->pool = r->pool;
      tf->log_level = r->request_body_file_log_level;
      tf->persistent = r->request_body_in_persistent_file;
      tf->clean = r->request_body_in_clean_file;

      ngx_create_temp_file(&tf->file, tf->path, tf->pool, tf->persistent, tf->clean, tf->access);

      ngx_file_t *dst = &tf->file;
      ngx_str_t chunk;
      chunk.data = ngx_pcalloc(r->pool, chunk_len);
      ngx_int_t scr_offset = 0;
      size_t dst_offset = 0;
      size_t write_len;
      size_t acct_num_chars = 11;

      ngx_regex_compile_t * rc;
      ngx_int_t offsetcount;
      int captures[2];
      ngx_str_t pat = ngx_string("\"acctNum\":");

      if(compile_regex(r,&rc,pat) != NGX_OK) {
        ngx_http_finalize_request(r,NGX_ERROR);
        return;
      };

      chunk.len = ngx_read_file(src, chunk.data, chunk_len, scr_offset);
      scr_offset = scr_offset + chunk.len;

      // removing leading spaces
      u_char *ptr = chunk.data;
      while(isspace(*ptr)) {
        if(ptr == chunk.data + chunk.len)  // All spaces?
        {
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: body first chunk is empty");
          ngx_http_finalize_request(r,NGX_ERROR);
          return;
        }
        ptr++;
        chunk.len--;
      }

      if(*ptr != '{')
      {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: body isn't a json object");
        if(ctx->waiting_more_body)
        {
          ctx->waiting_more_body = 0;
          r->write_event_handler = ngx_http_core_run_phases;
          ngx_http_core_run_phases(r);
        }

        ngx_http_finalize_request(r,ngx_http_output_filter(r, &out));
        return;
      }

      chunk.len--;
      chunk.data = ptr+1;

      ngx_str_t prov_chunk;
      prov_chunk.data = ngx_pcalloc(r->pool,chunk.len+acct_num_chars);
      ngx_memset(prov_chunk.data,'.',acct_num_chars);
      ngx_memcpy(prov_chunk.data + acct_num_chars, chunk.data,chunk.len);
      prov_chunk.len = chunk.len + acct_num_chars;

      chunk.data = prov_chunk.data;
      chunk.len = prov_chunk.len;
      
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: first chunk = %s", chunk.data);

      // writing correct acctNum
      write_len = ngx_write_file(dst,(u_char *)"{\n\"acctNum\": \"",14,dst_offset);
      dst_offset = dst_offset + write_len;
      write_len = ngx_write_file(dst,ctx->acct_num.data ,ctx->acct_num.len,dst_offset);
      dst_offset = dst_offset + write_len;
      write_len = ngx_write_file(dst,(u_char *)"\",\n" ,3,dst_offset);
      dst_offset = dst_offset + write_len;

      while(chunk.len > acct_num_chars)
      {

        offsetcount = ngx_regex_exec(rc->regex, &chunk, captures, 3);

        while(offsetcount >= 0)
        {
          ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: found acctNum on offset = %d", captures[0]);
          ngx_int_t p;
          for(p = 1; p < 8; p++ )
          {
            ngx_int_t offset_pos = captures[0]+p;
            *(chunk.data + offset_pos) = 'x';
          }
          offsetcount = ngx_regex_exec(rc->regex, &chunk, captures, 3);
        }

        write_len = ngx_write_file(dst,chunk.data+acct_num_chars,chunk.len-acct_num_chars,dst_offset);
        dst_offset = dst_offset + write_len;

        chunk.data = ngx_pcalloc(r->pool,chunk_len);
        chunk.len = ngx_read_file(src, chunk.data, chunk_len, scr_offset-acct_num_chars);
        scr_offset = scr_offset + chunk.len - acct_num_chars;

      }

      ngx_chain_t * cl;

      r->request_body->temp_file = tf;
      cl = ngx_chain_get_free_buf(r->pool, &r->request_body->free);
        if (cl == NULL) {
            ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            ngx_http_finalize_request(r,NGX_ERROR);
            return;
        }

        b = cl->buf;
        ngx_memzero(b, sizeof(ngx_buf_t));
        b->in_file = 1;
        b->file_last = r->request_body->temp_file->file.offset;
        b->file = &r->request_body->temp_file->file;

        r->request_body->bufs = cl;
        
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: file offset = %d",r->request_body->temp_file->file.offset );
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: dst offset = %d",dst->offset );
        r->headers_in.content_length_n = r->request_body->temp_file->file.offset;

    }
    else{
      ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: body in memory");

      ngx_str_t chunk;
      ngx_chain_t  *in = r->request_body->bufs;

      // removing leading spaces
      u_char *ptr = in->buf->pos; 
      while(isspace((unsigned char)*ptr)) {
        
        if(ptr == in->buf->last)  // All spaces?
        {
          ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: body first chunk is empty");
          in->next = NULL;
          ngx_http_finalize_request(r, NGX_ERROR);
          return;
        }

        ptr++;
      };
        
      in->buf->pos = ptr;
      
      //validating if it is an json object
      if(*ptr != '{')
      {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: body isn't a json object");
        ngx_http_finalize_request(r,ngx_http_output_filter(r, &out));
        return;
      }

      ngx_int_t content_len = 0;
      ngx_regex_compile_t * rc;
      ngx_int_t offsetcount;
      int captures[2];
      ngx_str_t pat = ngx_string("\"acctNum\":");

      if(compile_regex(r,&rc,pat) != NGX_OK) {
        ngx_http_finalize_request(r,NGX_ERROR);
        return;
      };

      while (in) {
        chunk.len = get_buffer_chunk(r,&chunk.data,in);
        ngx_int_t first_buf_len = in->buf->last - in->buf->pos;
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: buff len = %d", first_buf_len);

        offsetcount = ngx_regex_exec(rc->regex, &chunk, captures, 3);

        while(offsetcount >= 0)
        {
          ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: found acctNum on offset = %d", captures[0]);
          ngx_int_t p;
          for(p = 1; p < 8; p++ )
          {
            ngx_int_t offset_pos = captures[0]+p;
            if(offset_pos > first_buf_len){

              *(in->next->buf->pos + (offset_pos-first_buf_len)-6) = 'x';
            }
            else{
              *(in->buf->pos + offset_pos) = 'x';

            }
          }
          chunk.len = get_buffer_chunk(r,&chunk.data,in);
          offsetcount = ngx_regex_exec(rc->regex, &chunk, captures, 3);
        }

        content_len = content_len + first_buf_len;
        in = in->next;
      }


      //injecting correct acctNum
      ngx_buf_t *frst_buff = r->request_body->bufs->buf;
      ngx_int_t frst_buff_len = frst_buff->last - frst_buff->pos;
      
      ngx_int_t acct_num_prop_len = 13 + ctx->acct_num.len;
      ngx_buf_t *new_buf = ngx_create_temp_buf(r->pool, frst_buff_len + acct_num_prop_len);
      
      new_buf->start = new_buf->pos;
      u_char *pptr = ngx_cpymem(new_buf->pos,frst_buff->pos,1);
      pptr = ngx_cpymem(pptr,"\"acctNum\":\"",11);
      pptr = ngx_cpymem(pptr, ctx->acct_num.data ,ctx->acct_num.len);
      pptr = ngx_cpymem(pptr, "\"," ,2);
      new_buf->last = ngx_cpymem(pptr, frst_buff->pos+1,frst_buff_len-1);
      new_buf->end = new_buf->last;
      
      r->request_body->bufs->buf = new_buf;

      r->headers_in.content_length_n = content_len + ctx->acct_num.len + 13;

    }

  }

  ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"Keycloak: finish body");
  ctx->body_processed = NGX_OK;

  if(ctx->waiting_more_body)
  {
    ctx->waiting_more_body = 0;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
  }

  ngx_http_finalize_request(r,ngx_http_output_filter(r, &out));

  return;

}


//util functions

static ngx_int_t compile_regex(ngx_http_request_t *r, ngx_regex_compile_t **rc, ngx_str_t pattern){
    
    u_char errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t *new_rc;

    if ((new_rc = ngx_pcalloc(r->pool, sizeof(ngx_regex_compile_t))) == NULL) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to allocate memory to compile agent patterns");
      return NGX_ERROR;
    }
  
    new_rc->pattern = pattern;
    new_rc->pool = r->pool;
    new_rc->err.len = NGX_MAX_CONF_ERRSTR;
    new_rc->err.data = errstr;

    if (ngx_regex_compile(new_rc) != NGX_OK) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "unable to compile regex pattern %V", new_rc->pattern);
      return NGX_ERROR;
    };

    *rc = new_rc;

    return NGX_OK;

}

static size_t get_buffer_chunk (ngx_http_request_t  *r, u_char **chunk, ngx_chain_t  *current_chain){
  size_t buf_len = current_chain->buf->end- current_chain->buf->start;
  
  if(current_chain->next != NULL){
    size_t next_len = current_chain->next->buf->end- current_chain->next->buf->start;
    *chunk = ngx_palloc(r->pool, buf_len + next_len);
    u_char * pt_chunk = ngx_copy(*chunk,current_chain->buf->pos,buf_len);
    ngx_memcpy(pt_chunk,current_chain->next->buf->pos,next_len);

    return buf_len + next_len;
  }
  else{
    *chunk = ngx_palloc(r->pool, buf_len);
    ngx_memcpy(*chunk,current_chain->buf->pos,buf_len);
    return buf_len;
  }
}



//create_get_subrequest clone function (removed body and content length)

ngx_int_t create_get_subrequest(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args, ngx_http_request_t **psr,
    ngx_http_post_subrequest_t *ps, ngx_uint_t flags)
{
    ngx_time_t                    *tp;
    ngx_connection_t              *c;
    ngx_http_request_t            *sr;
    ngx_http_core_srv_conf_t      *cscf;
    ngx_http_postponed_request_t  *pr, *p;

    if (r->subrequests == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "subrequests cycle while processing \"%V\"", uri);
        return NGX_ERROR;
    }

    /*
     * 1000 is reserved for other purposes.
     */
    if (r->main->count >= 65535 - 1000) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "request reference counter overflow "
                      "while processing \"%V\"", uri);
        return NGX_ERROR;
    }

    if (r->subrequest_in_memory) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "nested in-memory subrequest \"%V\"", uri);
        return NGX_ERROR;
    }

    sr = ngx_pcalloc(r->pool, sizeof(ngx_http_request_t));
    if (sr == NULL) {
        return NGX_ERROR;
    }

    sr->signature = NGX_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;

    sr->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (sr->ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_list_init(&sr->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_list_init(&sr->headers_out.trailers, r->pool, 4,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    sr->pool = r->pool;

    ngx_http_clear_content_length(sr);
    ngx_http_clear_accept_ranges(sr);
    ngx_http_clear_last_modified(sr);

    sr->headers_in = r->headers_in;
    sr->headers_in.content_length_n = 0;


#if (NGX_HTTP_V2)
    sr->stream = r->stream;
#endif

    sr->method = NGX_HTTP_GET;
    sr->http_version = r->http_version;

    sr->request_line = r->request_line;
    sr->uri = *uri;

    if (args) {
        sr->args = *args;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    sr->subrequest_in_memory = (flags & NGX_HTTP_SUBREQUEST_IN_MEMORY) != 0;
    sr->waited = (flags & NGX_HTTP_SUBREQUEST_WAITED) != 0;
    sr->background = (flags & NGX_HTTP_SUBREQUEST_BACKGROUND) != 0;

    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = ngx_http_core_get_method;
    sr->http_protocol = r->http_protocol;
    sr->schema = r->schema;

    ngx_http_set_exten(sr);

    sr->main = r->main;
    sr->parent = r;
    sr->post_subrequest = ps;
    sr->read_event_handler = ngx_http_request_empty_handler;
    sr->write_event_handler = ngx_http_handler;

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    if (sr->subrequest_in_memory) {
        sr->filter_need_in_memory = 1;
    }

    if (!sr->background) {
        if (c->data == r && r->postponed == NULL) {
            c->data = sr;
        }

        pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
        if (pr == NULL) {
            return NGX_ERROR;
        }

        pr->request = sr;
        pr->out = NULL;
        pr->next = NULL;

        if (r->postponed) {
            for (p = r->postponed; p->next; p = p->next) { /* void */ }
            p->next = pr;

        } else {
            r->postponed = pr;
        }
    }

    sr->internal = 1;

    sr->discard_body = r->discard_body;
    sr->expect_tested = 1;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    sr->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;
    sr->subrequests = r->subrequests - 1;

    tp = ngx_timeofday();
    sr->start_sec = tp->sec;
    sr->start_msec = tp->msec;

    r->main->count++;

    *psr = sr;

    if (flags & NGX_HTTP_SUBREQUEST_CLONE) {
        sr->method = r->method;
        sr->method_name = r->method_name;
        sr->loc_conf = r->loc_conf;
        sr->valid_location = r->valid_location;
        sr->valid_unparsed_uri = r->valid_unparsed_uri;
        sr->content_handler = r->content_handler;
        sr->phase_handler = r->phase_handler;
        sr->write_event_handler = ngx_http_core_run_phases;

#if (NGX_PCRE)
        sr->ncaptures = r->ncaptures;
        sr->captures = r->captures;
        sr->captures_data = r->captures_data;
        sr->realloc_captures = 1;
        r->realloc_captures = 1;
#endif

        ngx_http_update_location_config(sr);
    }

    return ngx_http_post_request(sr, NULL);
}


