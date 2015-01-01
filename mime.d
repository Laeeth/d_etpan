module mime;

bool etpan_mime_is_text( mailmime * build_info)
{
  if (build_info.mm_type == MAILMIME_SINGLE) {
    if (isNull(build_info.mm_content_type)) {
//    if (build_info.mm_content_type != cast(mailmime_content*)0) {
      if (build_info.mm_content_type.ct_type.tp_type == MAILMIME_TYPE_DISCRETE_TYPE)
      {
        if (build_info.mm_content_type.ct_type.tp_data.tp_discrete_type.dt_type == MAILMIME_DISCRETE_TYPE_TEXT)
          return true;
      }
    }
    else
      return true;
  }
  return false;
}


/* display content type */

void show_part_info(File f,  mailmime_single_fields * mime_fields, mailmime_content * content)
{
  int col=0;
  int r;
  if ((mime_fields.fld_description==cast(char*)0))
    throw new Exception("show_part_info: description is NULL");

  if (mime_fields.fld_disposition_filename==cast(char*)0)
    throw new Exception("show_part_info: filename is NULL");

  auto description = ZtoString(mime_fields.fld_description);
  auto filename = ZtoString(mime_fields.fld_disposition_filename);

  f.writef(" [ Part "); 
  if (!isNull(content))
    throwOnError( mailmime_content_type_write(f.getFP(), &col, content),MAILIMF_NO_ERROR);
  f.writefln(" (%s) : %s ]\n", filename,description);
}

/*
  fetch the data of the mailmime_data structure whether it is a file
  or a string.

  data must be freed with mmap_string_unref()
*/

// this was disabled with #if 0 - not sure why
/*
void fetch_data(mailmime_data * data, char ** result, size_t * result_len)
{
  File fd;
  int r;
  char * text;
  struct stat buf;
  int res;
  MMAPString * mmapstr;

  switch (data.dt_type)
  {
    case MAILMIME_DATA_TEXT:
      mmapstr = throwOnError(mmap_string_new_len(data.dt_data.dt_text.dt_data, data.dt_data.dt_text.dt_length));
      * result = mmapstr.str;
      * result_len = mmapstr.len;
      return;

    case MAILMIME_DATA_FILE:
      fd = File(ZtoString(data.dt_data.dt_filename), "rb");
      if (getSize(fd) != 0)
      {
        text = mmap(NULL, buf.st_size, PROT_READ, MAP_SHARED, fd, 0);
        if (text == (char *)MAP_FAILED)
        {
  	res = ERROR_FILE;
  	goto close;
        }

        mmapstr = mmap_string_new_len(text, buf.st_size);
        if (mmapstr == NULL) {
          res = r;
          goto unmap;
        }
        
        munmap(text, buf.st_size);
      }
      else {
        mmapstr = mmap_string_new("");
        if (mmapstr == NULL) {
          res = r;
          goto close;
        }
      }

      close(fd);

      * result = mmapstr.str;
      * result_len = mmapstr.len;

      return NO_ERROR;

    default:
      return ERROR_INVAL;
  }
  
 unmap:
  munmap(text, buf.st_size);
 close:
  close(fd);
 err:
  return res;
}
*/



struct ETMIME
{
  mailmime_data *data;

  string getInfo()
  {
    switch (data.dt_type) {
    case MAILMIME_DATA_TEXT:
      return format("data : %s bytes", data.dt_data.dt_text.dt_length);
    case MAILMIME_DATA_FILE:
      return format("data (file) : %s\n", data.dt_data.dt_filename);
    default:
      return "unknown type";
    }
  }

  string[2] getParameter(mailmime_parameter * param)
  {
    string[] ret;
    ret[0]=ZtoString(param.pa_name);
    ret[1]=ZtoString(param.pa_value);
    return ret;
  }

  string getFilename(mailmime_disposition_parm * param)
  {
    if ((param.pa_type)!=MAILMIME_DISPOSITION_PARM_FILENAME)
      throw new Exception("d_etpan: unknown parameter type");
    return ZtoString(param.pa_data.pa_filename);
  }

  string getFilenames(mailmime_disposition * disposition)
  {
    string[] ret;
    clistiter * cur;

    for(cur = clist_begin(disposition.dsp_parms) ; cur != NULL ; cur = clist_next(cur))
    {
      mailmime_disposition_parm * param;
      param = clist_content(cur);
      ret~=getFilename(param);
    }
    return ret;
  }

  string[] getField(mailmime_field * field)
  {
    string[] ret;
    switch (field.fld_type) {
      case MAILMIME_FIELD_TYPE:
        ret~="content-type: ";
        ret~=display_mime_content(field.fld_data.fld_content);
        break;
      case MAILMIME_FIELD_DISPOSITION:
        ret~=getFilenames(field.fld_data.fld_disposition);
      break;
    }
    return ret;
  }

  string[] getFields(mailmime_fields * fields)
  {
    string[] ret;
    clistiter * cur;

    for(cur = clist_begin(fields.fld_list) ; cur != NULL ; cur = clist_next(cur)) {
      mailmime_field * field;

      field = clist_content(cur);
      ret~=getField(field);
    }
    return ret;
  }




static void display_from(struct mailimf_from * from)
{
  display_mailbox_list(from.frm_mb_list);
}

static void display_to(struct mailimf_to * to)
{
  display_address_list(to.to_addr_list);
}

static void display_cc(struct mailimf_cc * cc)
{
  display_address_list(cc.cc_addr_list);
}

static void display_subject(struct mailimf_subject * subject)
{
  printf("%s", subject.sbj_value);
}

string ETMIMETypeTable[int] = [ MAILMIME_DISCRETE_TYPE_TEXT: "text",
                                MAILMIME_DISCRETE_TYPE_IMAGE: "image",
                                MAILMIME_DISCRETE_TYPE_AUDIO: "audio",
                                MAILMIME_DISCRETE_TYPE_VIDEO: "video",
                                MAILMIME_DISCRETE_TYPE_APPLICATION: "application",
                                MAILMIME_DISCRETE_TYPE_EXTENSION: "extension"]; // mailmime_discrete_type.dt_extension


static void display_mime_composite_type(struct mailmime_composite_type * ct)
{
  switch (ct.ct_type) {
  case MAILMIME_COMPOSITE_TYPE_MESSAGE:
    printf("message");
    break;
  case MAILMIME_COMPOSITE_TYPE_MULTIPART:
    printf("multipart");
    break;
  case MAILMIME_COMPOSITE_TYPE_EXTENSION:
    printf("%s", ct.ct_token);
    break;
  }
}

static void display_mime_type(struct mailmime_type * type)
{
  switch (type.tp_type) {
  case MAILMIME_TYPE_DISCRETE_TYPE:
    display_mime_discrete_type(type.tp_data.tp_discrete_type);
    break;
  case MAILMIME_TYPE_COMPOSITE_TYPE:
    display_mime_composite_type(type.tp_data.tp_composite_type);
    break;
  }
}

static void display_mime_content(struct mailmime_content * content_type)
{
  printf("type: ");
  display_mime_type(content_type.ct_type);
  printf("/%s\n", content_type.ct_subtype);
}

static void display_mime(struct mailmime * mime)
{
  clistiter * cur;

  switch (mime.mm_type) {
    case MAILMIME_SINGLE:
    printf("single part\n");
    break;
    case MAILMIME_MULTIPLE:
    printf("multipart\n");
    break;
    case MAILMIME_MESSAGE:
    printf("message\n");
    break;
  }

  if (mime.mm_mime_fields != NULL) {
    if (clist_begin(mime.mm_mime_fields.fld_list) != NULL) {
      printf("MIME headers begin\n");
      display_mime_fields(mime.mm_mime_fields);
      printf("MIME headers end\n");
    }
  }

  display_mime_content(mime.mm_content_type);

  switch (mime.mm_type) {
    case MAILMIME_SINGLE:
    display_mime_data(mime.mm_data.mm_single);
    break;

    case MAILMIME_MULTIPLE:
    for(cur = clist_begin(mime.mm_data.mm_multipart.mm_mp_list) ; cur != NULL ; cur = clist_next(cur)) {
      display_mime(clist_content(cur));
    }
    break;

    case MAILMIME_MESSAGE:
    if (mime.mm_data.mm_message.mm_fields) {
      if (clist_begin(mime.mm_data.mm_message.mm_fields.fld_list) != NULL) {
        printf("headers begin\n");
        display_fields(mime.mm_data.mm_message.mm_fields);
        printf("headers end\n");
      }

      if (mime.mm_data.mm_message.mm_msg_mime != NULL) {
        display_mime(mime.mm_data.mm_message.mm_msg_mime);
      }
      break;
    }
  }
}


void mimeParse(string filename)
{
  int r;
   mailmime * mime;
  struct stat stat_info;
  ubyte[] data;
  size_t current_index;
  char * filename;

  f = File(filename,"rb");
  data.length=getSize(filename);
  fread(data, 1, stat_info.st_size, f);
  
  current_index = 0;
  throwOnError(mailmime_parse(data, stat_info.st_size, &current_index, &mime),MAILIMF_NO_ERROR) 
  display_mime(mime);
  mailmime_free(mime);
}


void save_mime_content(mailmessage * msg_info, struct mailmime * mime_part)
{
  char * body;
  size_t body_len;
  int r;
  char * filename;
  mailmime_single_fields fields;
  int res;

  memset(&fields, 0, sizeof(struct mailmime_single_fields));
  if (mime_part.mm_mime_fields != NULL)
    mailmime_single_fields_init(&fields, mime_part.mm_mime_fields, mime_part.mm_content_type);

  filename = fields.fld_disposition_filename;

  if (filename == NULL)
    if ((filename = fields.fld_content_name)==NULL)
      throw new Exception("d_etpan: invalid filename");

  scope(exit)
    mailmime_decoded_part_free(body);
  throwOnError(etpan_fetch_message(msg_info, mime_part, &fields, &body, &body_len),NO_ERROR);
  writefln("writing %s, %s bytes", filename, body_len);

  throwOnError(etpan_write_data(filename, body, body_len),NO_ERROR);
  mailmime_decoded_part_free(body);
  return;
}



/* fetch attachments */

void fetchMIME(File f, mailmessage * msg_info, mailmime * mime)
{
  clistiter * cur;
  mailmime_single_fields fields;
  int res;

  memset(&fields, 0, sizeof(struct mailmime_single_fields));
  if (mime.mm_mime_fields != NULL)
    mailmime_single_fields_init(&fields, mime.mm_mime_fields, mime.mm_content_type);

  switch(mime.mm_type) {
    case MAILMIME_SINGLE:
      save_mime_content(msg_info, mime);
      break;
      
    case MAILMIME_MULTIPLE:
      for(cur = clist_begin(mime.mm_data.mm_multipart.mm_mp_list) ; cur != NULL ; cur = clist_next(cur))
        throwOnError(etpan_fetch_mime(f, msg_info, clist_content(cur)),NO_ERROR);
      break;
        
    case MAILMIME_MESSAGE:
      if (mime.mm_data.mm_message.mm_msg_mime != NULL)
        throwOnError(etpan_fetch_mime(f, msg_info, mime.mm_data.mm_message.mm_msg_mime),NO_ERROR);
      break;
    default:
      break;
  }
  return;
}


void displayMIME()
{
  mailstorage * storage;
  mailfolder * folder;

   cached = (cache_directory != NULL);

  /* build the storage structure */

  throwOnError(storage = mailstorage_new(NULL));
  throwOnError(init_storage(storage, driver, server, port, connection_type,
      user, password, auth_type, path, cache_directory, flags_directory),MAIL_NO_ERROR);
    
  /* get the folder structure */

  throwOnError(folder = mailfolder_new(storage, path, NULL));
  throwOnError(mailfolder_connect(folder),MAIL_NO_ERROR));
  foreach(arg;args)
  {
    mailmessage * msg;
    uint32_t msg_num;
    mailmime * mime;
    msg_num = to!ulong(arg);

    scope(exit)
    {
      mailfolder_free(folder);
      mailstorage_free(storage);
    }
    throwOnError(mailsession_get_message(folder.fld_session, msg_num, &msg),MAIL_NO_ERROR);
    scope(exit)
    {
      mailmessage_free(msg);
      mailfolder_free(folder);
      mailstorage_free(storage);
    }
    throwOnError(mailmessage_get_bodystructure(msg, &mime),MAIL_NO_ERROR);
    throwOnError(etpan_fetch_mime(stdout, msg, mime),MAIL_NO_ERROR);
    mailmessage_free(msg);
  }
}






/* text is a string, build a mime part containing this string */

mailmime * build_body_text(string text)
{
  mailmime_fields * mime_fields;
  mailmime * mime_sub;
  mailmime_content * content;
  mailmime_parameter * param;

  /* text/plain part */

  throwOnException(mime_fields = mailmime_fields_new_encoding(MAILMIME_MECHANISM_8BIT));
  scope(exit)
    mailmime_fields_free(mime_fields);
  throwOnException(content = mailmime_content_new_with_str(toStringz("text/plain")));
  scope(exit)
  { mailmime_content_free(content); mailmime_fields_free(mime_fields);}

  throwOnException(param = mailmime_param_new_with_data(toStringz("charset"), DEST_CHARSET));
  r = clist_append(content.ct_parameters, param);
  if (r < 0) {
    mailmime_parameter_free(param);
    throwOnException(0,1);
  }

  throwOnException(mime_sub = mailmime_new_empty(content, mime_fields));
  scope(exit)
  {
    mailmime_free(mime_sub);
    mailmime_content_free(content);
    mailmime_fields_free(mime_fields);
  }

  throwOnException(mailmime_set_body_text(mime_sub, toStringz(text), text.length),MAILIMF_NO_ERROR);

  return mime_sub;

}


/* build a mime part containing the given file */

mailmime * build_body_file(string filename)
{
  mailmime_fields * mime_fields;
  mailmime * mime_sub;
  mailmime_content * content;
  mailmime_parameter * param;
  char *dup_filename=toStringz(filename);
  int r;

  /* text/plain part */

  mime_fields = mailmime_fields_new_filename(MAILMIME_DISPOSITION_TYPE_ATTACHMENT, dup_filename, MAILMIME_MECHANISM_BASE64);
  if (mime_fields == NULL)
    throw new Exception("d_etpan MIME build");

  scope(exit)
    mailmime_fields_free(mime_fields);

  throwOnException(mailmime_content_new_with_str(toStringz("text/plain")));

  scope(exit)
    { mailmime_content_free(content); mailmime_fields_free(mime_fields);}

  throwOnException(param = mailmime_param_new_with_data(toStringz("charset"), DEST_CHARSET));
  auto r=clist_append(content.ct_parameters, param);
  if (r < 0) {
    mailmime_parameter_free(param);
    throw new Exception("d_etpan MIME build");
  }

  throwOnException(mime_sub = mailmime_new_empty(content, mime_fields));
  dup_filename = toStringz(filename);
  throwOnException(mailmime_set_body_file(mime_sub, dup_filename),MAILIMF_NO_ERROR));
  
  return mime_sub;
}

/* build an empty message */

mailmime * build_message(mailimf_fields * fields)
{
  mailmime * mime;
  
  /* message */
  
  mime = mailmime_new_message_data(NULL);
  if (mime == NULL) {
    goto err;
  }

  mailmime_set_imf_fields(mime, fields);

  return mime;

 err:
  return cast(mailmime*)NULL;
}


void composeMIMEMessage(buf[] text, string filename)
{
  mailimf_fields * fields;
  string text;
  string filename;
  mailmime * message;
  mailmime * text_part;
  mailmime * file_part;
  int col;

  fields = build_fields();
  scope(exit)
      mailimf_fields_free(fields);

  text_part = build_body_text(text);
  scope(exit) {mailmime_free(text_part); mailimf_fields_free(fields);}
  message = build_message(fields);
  scope(exit) {mailmime_free(text_part); mailimf_fields_free(fields); mailmime_free(message);}
  file_part = build_body_file(filename);
  scope(exit) {mailmime_free(text_part); mailimf_fields_free(fields); mailmime_free(message);  mailmime_free(file_part);}
  throwOnException(mailmime_smart_add_part(message, text_part),MAILIMF_NO_ERROR);

  scope(exit) {
    mailmime_free(file_part);
    mailmime_free(text_part);
    mailmime_free(message);
    mailimf_fields_free(fields);
  }
  throwOnException(mailmime_smart_add_part(message, file_part),MAILIMF_NO_ERROR);
  col = 0;
  mailmime_write(cast(FILE*)stdout, &col, message);
}



// create mime file

mailimf_fields * build_fields()
{
  mailimf_fields * fields;
  mailimf_field * f;
  clist * list;
  mailimf_from * from;
  mailimf_to * to;
  mailimf_mailbox * mb;
  mailimf_address * addr;
  mailimf_mailbox_list * mb_list;
  mailimf_address_list * addr_list;
  clist * fields_list;

  /* build headers */

  fields_list = clist_new();
  
  /* build header 'From' */
  
  list = clist_new();
  mb = mailimf_mailbox_new(strdup("DINH =?iso-8859-1?Q?Vi=EAt_Ho=E0?="),
    strdup("dinh.viet.hoa@foobaremail.com"));
  clist_append(list, mb);
  mb_list = mailimf_mailbox_list_new(list);
  
  from = mailimf_from_new(mb_list);
  
  f = mailimf_field_new(MAILIMF_FIELD_FROM,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    from, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL);

  clist_append(fields_list, f);
  
  /* build header To */

  list = clist_new();
  mb = mailimf_mailbox_new(strdup("DINH =?iso-8859-1?Q?Vi=EAt_Ho=E0?="),
    strdup("dinh.viet.hoa@foobaremail.com"));
  addr = mailimf_address_new(MAILIMF_ADDRESS_MAILBOX, mb, NULL);
  clist_append(list, addr);
  addr_list = mailimf_address_list_new(list);
  
  to = mailimf_to_new(addr_list);

  f = mailimf_field_new(MAILIMF_FIELD_TO,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, to, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL);
  
  clist_append(fields_list, f);
  
  fields = mailimf_fields_new(fields_list);
  
  return fields;
}

mailmime * part_new_empty(struct mailmime_content * content, struct mailmime_fields * mime_fields,
  const char * boundary_prefix, int force_single)
{
  mailmime * build_info;
  clist * list;
  int r;
  int mime_type;

  list = NULL;

  if (force_single) {
    mime_type = MAILMIME_SINGLE;
  }
  else {
    switch (content.ct_type.tp_type) {
      case MAILMIME_TYPE_DISCRETE_TYPE:
      mime_type = MAILMIME_SINGLE;
      break;

      case MAILMIME_TYPE_COMPOSITE_TYPE:
      switch (content.ct_type.tp_data.tp_composite_type.ct_type) {
        case MAILMIME_COMPOSITE_TYPE_MULTIPART:
        mime_type = MAILMIME_MULTIPLE;
        break;

        case MAILMIME_COMPOSITE_TYPE_MESSAGE:
        if (strcasecmp(content.ct_subtype, "rfc822") == 0)
          mime_type = MAILMIME_MESSAGE;
        else
          mime_type = MAILMIME_SINGLE;
        break;

        default:
        goto err;
      }
      break;

      default:
      goto err;
    }
  }

  if (mime_type == MAILMIME_MULTIPLE) {
    char * attr_name;
    char * attr_value;
    struct mailmime_parameter * param;
    clist * parameters;
    char * boundary;

    list = clist_new();
    if (list == NULL)
      goto err;

    attr_name = strdup("boundary");
    boundary = generate_boundary(boundary_prefix);
    attr_value = boundary;
    if (attr_name == NULL) {
      free(attr_name);
      goto free_list;
    }

    param = mailmime_parameter_new(attr_name, attr_value);
    if (param == NULL) {
      free(attr_value);
      free(attr_name);
      goto free_list;
    }

    if (content.ct_parameters == NULL) {
      parameters = clist_new();
      if (parameters == NULL) {
        mailmime_parameter_free(param);
        goto free_list;
      }
    }
    else
      parameters = content.ct_parameters;

    r = clist_append(parameters, param);
    if (r != 0) {
      clist_free(parameters);
      mailmime_parameter_free(param);
      goto free_list;
    }

    if (content.ct_parameters == NULL)
      content.ct_parameters = parameters;
  }

  build_info = mailmime_new(mime_type,
    NULL, 0, mime_fields, content,
    NULL, NULL, NULL, list,
    NULL, NULL);
  if (build_info == NULL) {
    clist_free(list);
    return NULL;
  }

  return build_info;

  free_list:
  clist_free(list);
  err:
  return NULL;
}

mailmime * get_text_part(const char * mime_type, const char * text, size_t length, int encoding_type)
{
  mailmime_fields * mime_fields;
  mailmime * mime;
  mailmime_content * content;
  mailmime_parameter * param;
  mailmime_disposition * disposition;
  mailmime_mechanism * encoding;
    
  encoding = mailmime_mechanism_new(encoding_type, NULL);
  disposition = mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_INLINE, NULL, NULL, NULL, NULL, (size_t) -1);
  mime_fields = mailmime_fields_new_with_data(encoding, NULL, NULL, disposition, NULL);

  content = mailmime_content_new_with_str(mime_type);
  param = mailmime_param_new_with_data("charset", "utf-8");
  clist_append(content.ct_parameters, param);
  mime = part_new_empty(content, mime_fields, NULL, 1);
  mailmime_set_body_text(mime, (char *) text, length);
  return mime;
}

enum TEXT= "You'll find a file as attachment";

mailmime * get_plain_text_part()
{
  int mechanism;

  mechanism = MAILMIME_MECHANISM_QUOTED_PRINTABLE;
  return get_text_part("text/plain", TEXT, sizeof(TEXT) - 1, mechanism);
}

mailmime * get_file_part(const char * filename, const char * mime_type, const char * text, size_t length)
{
  char * disposition_name;
  int encoding_type;
  mailmime_disposition * disposition;
  mailmime_mechanism * encoding;
  mailmime_content * content;
  mailmime * mime;
  mailmime_fields * mime_fields;
  
  disposition_name = NULL;
  if (filename != NULL) {
    disposition_name = strdup(filename);
  }
  disposition = mailmime_disposition_new_with_data(MAILMIME_DISPOSITION_TYPE_ATTACHMENT, disposition_name, NULL, NULL, NULL, (size_t) -1);
  content = mailmime_content_new_with_str(mime_type);
  
  encoding_type = MAILMIME_MECHANISM_BASE64;
  encoding = mailmime_mechanism_new(encoding_type, NULL);
  mime_fields = mailmime_fields_new_with_data(encoding, NULL, NULL, disposition, NULL);
  mime = part_new_empty(content, mime_fields, NULL, 1);
  mailmime_set_body_text(mime, (char *) text, length);
  
  return mime;
}

enum FILEDATA= "SOME-IMAGE-DATA";

mailmime * get_sample_file_part()
{
  mailmime * part;
  
  part = get_file_part("file-data.jpg", "image/jpeg", FILEDATA, sizeof(FILEDATA) - 1);

  return part;
}

enum MAX_MESSAGE_ID=512;

static char * generate_boundary(const char * boundary_prefix)
{
    char id[MAX_MESSAGE_ID];
    time_t now;
    char name[MAX_MESSAGE_ID];
    long value;
    
    now = time(NULL);
    value = random();
    gethostname(name, MAX_MESSAGE_ID);
    
    if (boundary_prefix == NULL)
        boundary_prefix = "";
    
    snprintf(id, MAX_MESSAGE_ID, "%s%lx_%lx_%x", boundary_prefix, now, value, getpid());
    
    return strdup(id);
}

mailmime * part_multiple_new(const char * type, const char * boundary_prefix)
{
    mailmime_fields * mime_fields;
    mailmime_content * content;
    mailmime * mp;
    
    mime_fields = mailmime_fields_new_empty();
    if (mime_fields == NULL)
        goto err;
    
    content = mailmime_content_new_with_str(type);
    if (content == NULL)
        goto free_fields;
    
    mp = part_new_empty(content, mime_fields, boundary_prefix, 0);
    if (mp == NULL)
        goto free_content;
    
    return mp;
    
free_content:
    mailmime_content_free(content);
free_fields:
    mailmime_fields_free(mime_fields);
err:
    return NULL;
}

mailmime * get_multipart_mixed(const char * boundary_prefix)
{
  mailmime * mime;
  mime = part_multiple_new("multipart/mixed", boundary_prefix);
  return mime;
}

void buildMIME()
{
  mailmime * msg_mime;
  mailmime * mime;
  mailmime * submime;
  mailimf_fields * fields;
  int col;
  
  msg_mime = mailmime_new_message_data(NULL);
  fields = build_fields();
  mailmime_set_imf_fields(msg_mime, fields);
  
  mime = get_multipart_mixed(NULL);
  
  submime = get_plain_text_part();
  mailmime_smart_add_part(mime, submime);
  submime = get_sample_file_part();
  mailmime_smart_add_part(mime, submime);
  
  mailmime_add_part(msg_mime, mime);

  col = 0;
  mailmime_write_file(stdout, &col, mime);

  mailmime_free(msg_mime);

  exit(0);
}

