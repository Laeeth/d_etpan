import d_etpan;
import std.stdio;
import std.string;
import std.file;
import core.stdc.time;
//import std.c.linux.linux;

enum DEST_CHARSET="iso-8859-1";
enum NULL=cast(void*)0;
/* build sample fields */

mailimf_fields *build_fields()
{
  mailimf_mailbox_list * from;
  mailimf_address_list * to;
  string subject = "this is a sample";
  int r;
  mailimf_fields * new_fields;

  from = mailimf_mailbox_list_new_empty();
  if (from == NULL) {
    goto err;
  }

  r = mailimf_mailbox_list_add_parse(from,toStringz("DINH Viet Hoa <hoa@sourceforge.net>"));
  if (r != MAILIMF_NO_ERROR) {
    goto free_from;
  }

  /* to field */

  to = mailimf_address_list_new_empty();
  if (to == NULL) {
    goto free_from;
  }

  r = mailimf_address_list_add_parse(to, toStringz("Paul <claws@thewildbeast.co.uk>"));
  if (r != MAILIMF_NO_ERROR) {
    goto free_to;
  }

  new_fields = mailimf_fields_new_with_data(from /* from */,
      NULL /* sender */, NULL /* reply-to */, 
      to, NULL /* cc */, NULL /* bcc */, NULL /* in-reply-to */,
      NULL /* references */,
      toStringz(subject));
  if (new_fields == NULL)
    goto free_to;

  return new_fields;

 free_to:
  mailimf_address_list_free(to);
 free_from:
  mailimf_mailbox_list_free(from);
 err:
  return cast(mailimf_fields*)0;
}



/* text is a string, build a mime part containing this string */

mailmime * build_body_text(string text)
{
  mailmime_fields * mime_fields;
  mailmime * mime_sub;
  mailmime_content * content;
  mailmime_parameter * param;
  int r;

  /* text/plain part */

  mime_fields = mailmime_fields_new_encoding(MAILMIME_MECHANISM_8BIT);
  if (mime_fields == NULL) {
    goto err;
  }

  content = mailmime_content_new_with_str(toStringz("text/plain"));
  if (content == NULL) {
    goto free_fields;
  }

  param = mailmime_param_new_with_data(toStringz("charset"), DEST_CHARSET);
  if (param == NULL) {
    goto free_content;
  }

  r = clist_append(content.ct_parameters, param);
  if (r < 0) {
    mailmime_parameter_free(param);
    goto free_content;
  }

  mime_sub = mailmime_new_empty(content, mime_fields);
  if (mime_sub == NULL) {
    goto free_content;
  }

  r = mailmime_set_body_text(mime_sub, toStringz(text), text.length);
  if (r != MAILIMF_NO_ERROR) {
    goto free_mime;
  }

  return mime_sub;

 free_mime:
  mailmime_free(mime_sub);
  goto err;
 free_content:
  mailmime_content_free(content);
 free_fields:
  mailmime_fields_free(mime_fields);
 err:
  return cast(mailmime*)0;
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

  mime_fields =
    mailmime_fields_new_filename(MAILMIME_DISPOSITION_TYPE_ATTACHMENT,
        dup_filename, MAILMIME_MECHANISM_BASE64);
  if (mime_fields == NULL)
    goto err;

  content = mailmime_content_new_with_str(toStringz("text/plain"));
  if (content == NULL) {
    goto free_fields;
  }

  param = mailmime_param_new_with_data(toStringz("charset"), DEST_CHARSET);
  if (param == NULL) {
    goto free_content;
  }

  r = clist_append(content.ct_parameters, param);
  if (r < 0) {
    mailmime_parameter_free(param);
    goto free_content;
  }

  mime_sub = mailmime_new_empty(content, mime_fields);
  if (mime_sub == NULL) {
    goto free_content;
  }

  dup_filename = toStringz(filename);

  r = mailmime_set_body_file(mime_sub, dup_filename);
  if (r != MAILIMF_NO_ERROR) {
    goto free_mime;
  }

  return mime_sub;

 free_mime:
  mailmime_free(mime_sub);
  goto err;
 free_content:
  mailmime_content_free(content);
 free_fields:
  mailmime_fields_free(mime_fields);
  goto err;
 err:
  return cast(mailmime*)0;
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


int main(string[] args)
{
  mailimf_fields * fields;
  string text;
  string filename;
  mailmime * message;
  mailmime * text_part;
  mailmime * file_part;
  int r;
  int col;

  if (args.length < 3) {
    writef("syntax: compose-msg \"text\" filename\n");
    return 1;
  }

  fields = build_fields();
  if (fields == NULL)
    goto err;

  message = build_message(fields);
  if (message == NULL)
    goto free_fields;

  text = args[1];
  text_part = build_body_text(text);
  if (text_part == NULL)
    goto free_message;

  filename = args[2];
  file_part = build_body_file(filename);
  if (file_part == NULL)
    goto free_text;

  r = mailmime_smart_add_part(message, text_part);
  if (r != MAILIMF_NO_ERROR)
    goto free_file;

  r = mailmime_smart_add_part(message, file_part);
  if (r != MAILIMF_NO_ERROR)
    goto free_file_alone;
  
  col = 0;
  mailmime_write(cast(FILE*)stdout, &col, message);

  mailmime_free(message);

  return 0;

 free_file_alone:
  mailmime_free(file_part);
  goto free_text;
 free_file:
  mailmime_free(file_part);
 free_text:
  mailmime_free(text_part);
 free_message:
  mailmime_free(message);
  goto err;
 free_fields:
  mailimf_fields_free(fields);
 err:
  writef("error memory\n");
  return 1;
}
